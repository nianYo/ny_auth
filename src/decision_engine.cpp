#include "decision_engine.h"

#include <sstream>

// ======================================================
// 构造函数
// 作用：保存缓存对象、DAO 对象和缓存 TTL
// ======================================================
DecisionEngine::DecisionEngine(std::shared_ptr<LocalCache<UserPermSet>> cache, std::shared_ptr<PermissionDAO> dao, int cache_ttl) : cache_(std::move(cache)), dao_(std::move(dao)), cache_ttl_(cache_ttl) {}

// ======================================================
// Evaluate
// 作用：执行一次完整的权限决策
// ======================================================
DecisionResult DecisionEngine::Evaluate(const DecisionRequest& request) {
    
    DecisionResult result;

    if(!dao_) {
        
        result.allowed = false;
        result.reason = "系统内部错误：DAO未初始化";
        result.deny_code = "INTERNAL_ERROR";
        result.trace_text = "decision engine has no dao instance";
        return result;
    }

    // --------------------------------------------------
    // 1) 校验请求参数
    // --------------------------------------------------
    if(!validateRequest(request, result)) {
        return result;
    }

    // --------------------------------------------------
    // 2) 查询应用信息
    //    - 看 app 是否存在
    //    - 看 app 是否启用
    //    - 拿到 policy_version
    // --------------------------------------------------
    auto app_info_opt = dao_->getAppInfo(request.app_code);

    if(!app_info_opt.has_value()) {
        
        result.allowed = false;
        result.reason = "应用不存在";
        result.deny_code = "APP_NOT_FOUND";
        result.policy_version = 1;
        result.trace_text = "app not found for app_code = " + request.app_code;
        
        return result;
    }

    const AppInfo app_info = app_info_opt.value();
    result.policy_version = app_info.policy_version;

    if(!app_info.enabled) {
        
        result.allowed = false;
        result.reason = "应用已被禁用";
        result.deny_code = "APP_DISABLED";
        result.trace_text = "app exists but disabled, app_code = " + request.app_code;

        return result;
    }

    // --------------------------------------------------
    // 3) 判断目标权限是否存在
    //    这一步很重要，因为：
    //    - 权限不存在
    //    - 用户没有该权限
    //    是两种完全不同的情况
    // --------------------------------------------------
    if(!dao_->permissionExists(request.app_code, request.perm_key)) {

        result.allowed = false;
        result.reason = "权限不存在";
        result.deny_code = "PERMISSION_NOT_FOUND";
        result.current_roles = dao_->getUserRoles(request.app_code, request.user_id);
        result.trace_text = "permission not found, perm_key = "+request.perm_key;

        return result;
    }

    // --------------------------------------------------
    // 4) 如果请求里带了资源信息，就先检查资源是否存在、是否启用
    //    这样后面 owner 规则和 RBAC 都是在“资源有效”的前提下做判断
    // --------------------------------------------------
    if(!request.resource_type.empty() && !request.resource_id.empty()) {
        
        auto resource_info_opt = dao_->getResourceInfo(request.app_code, request.resource_type, request.resource_id);

        if(!resource_info_opt.has_value()) {

            result.allowed = false;
            result.reason = "资源不存在";
            result.deny_code = "RESOURCE_NOT_FOUND";
            result.trace_text = "resource not found, resource_type = " + request.resource_type + ", resource_id = " + request.resource_id;

            return result;
        }

        const ResourceInfo resource_info = resource_info_opt.value();

        if(!resource_info.enabled) {
            
            result.allowed = false;
            result.reason = "资源不存在或已被禁用";
            result.deny_code = "RESOURCE_NOT_FOUND";
            result.trace_text = "resource exists but disabled, resource_type = " + request.resource_type + ", resource_id = " + request.resource_id;

            return result;
        }
    }
    // --------------------------------------------------
    // 5) 先尝试 owner 快捷规则
    //    例如：
    //    - 这篇文档是你自己的
    //    - 且 document:edit 允许 owner 快捷通过
    // --------------------------------------------------
    if(tryOwnerShortcut(request, result)) {

        DecisionLogRecord log_record;
        log_record.app_id = app_info.app_id;
        log_record.app_code = app_info.app_code;
        log_record.user_id = request.user_id;
        log_record.perm_key = request.perm_key;
        log_record.resource_type = request.resource_type;
        log_record.resource_id = request.resource_id;
        log_record.allowed = result.allowed;
        log_record.decision_source = decisionSourceToString(result.decision_source);
        log_record.matched_roles_csv = joinStrings(result.matched_roles);
        log_record.matched_permissions_csv = joinStrings(result.matched_permissions);
        log_record.owner_shortcut_used = result.owner_shortcut_used;
        log_record.policy_version = result.policy_version;
        log_record.deny_code = result.deny_code;
        log_record.reason = result.reason;
        log_record.trace_text = result.trace_text;

        dao_->insertDecisionLog(log_record);

        return result;
    }

    // --------------------------------------------------
    // 6) owner 没有直接放行，就加载该用户的权限集合
    //    这里会先查缓存，缓存 miss 再查数据库
    // --------------------------------------------------
    UserPermSet user_permissions = loadUserPermissions(request.app_code, request.user_id, result.policy_version, result);

    // --------------------------------------------------
    // 7) 走标准 RBAC 权限判断
    // --------------------------------------------------
    evaluateByRbac(request, user_permissions, result);

    // --------------------------------------------------
    // 8) 记录决策日志（失败也记录）
    // --------------------------------------------------
    DecisionLogRecord log_record;
    log_record.app_id = app_info.app_id;
    log_record.app_code = app_info.app_code;
    log_record.user_id = request.user_id;
    log_record.perm_key = request.perm_key;
    log_record.resource_type = request.resource_type;
    log_record.resource_id = request.resource_id;
    log_record.allowed = result.allowed;
    log_record.decision_source = decisionSourceToString(result.decision_source);
    log_record.matched_roles_csv = joinStrings(result.matched_roles);
    log_record.matched_permissions_csv = joinStrings(result.matched_permissions);
    log_record.owner_shortcut_used = result.owner_shortcut_used;
    log_record.policy_version = result.policy_version;
    log_record.deny_code = result.deny_code;
    log_record.reason = result.reason;
    log_record.trace_text = result.trace_text;

    dao_->insertDecisionLog(log_record);

    return result;
}

// ======================================================
// validateRequest
// 作用：检查请求参数是否合法
// ======================================================
bool DecisionEngine::validateRequest(const DecisionRequest& request, DecisionResult& result) {
    
    if(request.app_code.empty()) {
       
        result.allowed = false;
        result.reason = "参数不完整：app_code 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "request validation failed: empty app_code";

        return false;
    }

    if(request.user_id.empty()) {
       
        result.allowed = false;
        result.reason = "参数不完整：user_id 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "request validation failed: empty user_id";

        return false;
    }

    if(request.perm_key.empty()) {
       
        result.allowed = false;
        result.reason = "参数不完整：perm_key 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "request validation failed: empty perm_key";

        return false;
    }

    const bool has_resource_type = !request.resource_type.empty();
    const bool has_resource_id = !request.resource_id.empty();

    if(has_resource_type != has_resource_id) {

        result.allowed = false;
        result.reason = "参数不完整：resource_type 和 resource_id 必须同时提供";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "request validation failed: resource_type/resource_id mismatch";

        return false;
    }

    return true;
}

// ======================================================
// loadUserPermissions
// 作用：加载用户权限集合
// 流程：
// 1. 先拼缓存 key
// 2. 查缓存
// 3. miss 再查数据库
// 4. 把数据库结果回写缓存
// ======================================================
DecisionEngine::UserPermSet DecisionEngine::loadUserPermissions (const std::string& app_code, const std::string& user_id, int policy_version, DecisionResult& result) {

    UserPermSet user_permissions;

    const std::string cache_key = BuildPermissionCacheKey(app_code, user_id, policy_version);

    if(cache_) {

        if(cache_->Get(cache_key, user_permissions)) {

            result.decision_source = DecisionSourceType::kCache;

            return user_permissions;
        }
    }

    auto permissions = dao_->getUserPermissions(app_code, user_id);

    for(const auto& perm : permissions) {
        
        user_permissions.insert(perm);
    }

    if(cache_) {

        cache_->Put(cache_key, user_permissions, cache_ttl_);
    }

    result.decision_source = DecisionSourceType::kDatabase;

    return user_permissions;
}

// ======================================================
// tryOwnerShortcut
// 作用：尝试走 owner 快捷规则
// 返回：
//   true  -> 已经放行，不需要继续走 RBAC
//   false -> 没有通过 owner 规则，继续走 RBAC
// ======================================================
bool DecisionEngine::tryOwnerShortcut(const DecisionRequest& request, DecisionResult& result) {

    if(request.resource_type.empty() || request.resource_id.empty()) {
        return false;
    }

    if (!dao_->isOwnerShortcutEnabled(request.app_code, request.perm_key)) {
        return false;
    }

    const bool is_owner = dao_->isResourceOwner(request.app_code, request.resource_type, request.resource_id, request.user_id);

    if(!is_owner) {
        return false;
    }

    result.allowed = true;
    result.reason = "资源 owner 快捷规则允许访问";
    result.deny_code = "OK";
    result.owner_shortcut_used = true;
    result.decision_source = DecisionSourceType::kDatabase;
    result.current_roles = dao_->getUserRoles(request.app_code, request.user_id);
    result.matched_permissions.push_back(request.perm_key);
    result.trace_text = "owner shortcut matched: user_id = " + request.user_id + ", resource_id = " + request.resource_id + ", perm_key = " + request.perm_key;

    return true;
}

// ======================================================
// evaluateByRbac
// 作用：执行标准 RBAC 权限判断
// ======================================================
void DecisionEngine::evaluateByRbac(const DecisionRequest& request, const UserPermSet& user_permissions, DecisionResult& result) {

    result.current_roles = dao_->getUserRoles(request.app_code, request.user_id);

    const std::vector<std::string> candidate_roles = dao_->getRolesWithPermission(request.app_code, request.perm_key);

    if(result.current_roles.empty()) {
        
        result.allowed = false;
        result.reason = "用户未分配任何角色";
        result.deny_code = "USER_HAS_NO_ROLE";
        result.suggest_roles = candidate_roles;
        result.trace_text = "rbac denied: user has no role, required_permission = " + request.perm_key;

        return;
    }

    const bool permission_matched = (user_permissions.find(request.perm_key) != user_permissions.end());

    if(permission_matched) {

        result.allowed = true;
        result.reason = "用户权限允许访问";
        result.deny_code = "OK";
        result.matched_permissions.push_back(request.perm_key);

        for(const auto& current_role : result.current_roles) {
            
            for(const auto& candidate_role : candidate_roles) {

                if(current_role == candidate_role) {
                    result.matched_roles.push_back(current_role);
                }
            }
        }

        result.trace_text = "rbac allowed: current_roles = [" + joinStrings(result.current_roles) + "], matched_roles = [" + joinStrings(result.matched_roles) + "], perm_key = " + request.perm_key + ", source = " + decisionSourceToString(result.decision_source);

        return;
    }

    result.allowed = false;
    result.reason = "用户没有该权限";
    result.deny_code = "PERMISSION_DENIED";
    result.suggest_roles = candidate_roles;

    result.trace_text = "rbac denied: current_roles = [" + joinStrings(result.current_roles) + "], required_permission = " + request.perm_key + ", suggest_roles = [" + joinStrings(result.suggest_roles) + "], source = " + decisionSourceToString(result.decision_source);
}

// ======================================================
// joinStrings
// 作用：把字符串数组拼成逗号分隔字符串
// ======================================================
std::string DecisionEngine::joinStrings(const std::vector<std::string>& items) const {
    
    if(items.empty()) {
        return "";
    }

    std::ostringstream oss;
    for(std::size_t i = 0; i < items.size(); ++i) {
        if(i > 0) {
            oss << ",";
        }
        oss << items[i];
    }

    return oss.str();
}

// ======================================================
// decisionSourceToString
// 作用：把内部枚举转换成字符串
// ======================================================
std::string DecisionEngine::decisionSourceToString(DecisionSourceType source) const {
    switch(source) {
        case DecisionSourceType::kCache:
            return "CACHE";
        case DecisionSourceType::kDatabase:
            return "DB";
        case DecisionSourceType::kUnknown:
        default:
            return "UNKNOWN";
    }
}