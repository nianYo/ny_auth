#include "simulation_engine.h"

#include <algorithm>
#include <sstream>

// ======================================================
// 构造函数
// 作用：保存运行时 DAO 和管理端 DAO
// ======================================================
SimulationEngine::SimulationEngine(std::shared_ptr<PermissionDAO> permission_dao, std::shared_ptr<AdminDAO> admin_dao) : permission_dao_(std::move(permission_dao)), admin_dao_(std::move(admin_dao)) {}

// ======================================================
// Simulate
// 作用：执行一次完整的模拟检查
//
// 流程：
// 1. 校验基础参数
// 2. 校验 app 是否存在、是否启用
// 3. 校验目标权限是否存在
// 4. 如果带资源，校验资源是否存在/启用
// 5. 校验模拟输入里引用到的角色 / 权限是否存在
// 6. 构造“模拟后的有效角色集合”
// 7. 构造“模拟后的有效权限集合”
// 8. 先尝试 owner 快捷规则
// 9. 再走模拟版 RBAC 判断
// ======================================================
SimulationResult SimulationEngine::Simulate(const SimulationRequest& request) {

    SimulationResult result;

    if(!permission_dao_ || !admin_dao_) {

        result.allowed = false;
        result.reason = "系统内部错误：模拟引擎依赖未初始化";
        result.deny_code = "INTERNAL_ERROR";
        result.trace_text = "simulation engine missing dao denpendency";

        return result;
    }

    if(!validateRequest(request, result)){

        return result;
    }

    auto app_info_opt = permission_dao_->getAppInfo(request.app_code);

    if(!app_info_opt.has_value()) {

        result.allowed = false;
        result.reason = "应用不存在";
        result.deny_code = "APP_NOT_FOUND";
        result.policy_version = 1;
        result.trace_text = "simulation dailed: app not found, app_code = " + request.app_code;

        return result;
    }

    const AppInfo app_info = app_info_opt.value();

    result.policy_version = app_info.policy_version;

    if(!app_info.enabled) {

        result.allowed = false;
        result.reason = "应用已被禁用";
        result.deny_code = "APP_DESABLED";
        result.trace_text = "simulation dailed: app disabled, app_code = " + request.app_code;

        return result;
    }

    if(!permission_dao_->permissionExists(request.app_code, request.perm_key)) {

        result.allowed = false;
        result.reason = "权限不存在";
        result.deny_code = "PERMISSION_NOT_FOUND";
        result.trace_text = "simulation failed: permission not found, perm_key = " + request.perm_key;

        return result;
    }

    if(!request.resource_type.empty() && !request.resource_id.empty()) {

        auto resource_info_opt = permission_dao_->getResourceInfo(request.app_code, request.resource_type, request.resource_id);

        if(!resource_info_opt.has_value()) {

            result.allowed = false;
            result.reason = "资源不存在";
            result.deny_code = "RESOURCE_NOT_FOUND";
            result.trace_text = "simulation falied:resource not found, resource_type = " + request.resource_type + ", resource_id = " + request.resource_id;

            return result;
        }

        const ResourceInfo resource_info = resource_info_opt.value();

        if(!resource_info.enabled) {

            result.allowed = false;
            result.reason = "资源不存在或已被禁用";
            result.deny_code = "RESOURCE_NOT_FOUND";
            result.trace_text = "simulation failed: resource exists but disabled,  resource_type = " + request.resource_type + ", resource_id = " + request.resource_id;

            return result;
        }

        for(const auto& grant : request.simulated_grants) {

            if(grant.role_key.empty()) {

                result.allowed = false;
                result.reason = "模拟输入错误：simulated_grants 中 role_key 不能为空";
                result.deny_code = "INVALID_ARGUMENT";
                result.trace_text = "simulation validation failed: empty role_key in simulated_grants";

                return result;
            }

            if(!admin_dao_->roleExists(request.app_code, grant.role_key)) {

                result.allowed = false;
                result.reason = "模拟输入引用了不存在的角色";
                result.deny_code = "NOT_FOUND";
                result.trace_text = "simulation validation failed: role not found, role_key = " + grant.role_key;

                return result;
            }
        }

        for(const auto& binding : request.simulated_bindings) {

            if(binding.role_key.empty() || binding.perm_key.empty()) {

                result.allowed = false;
                result.reason = "模拟输入错误：simulated_bindings 中 role_key / perm_key 不能为空";
                result.deny_code = "INVALID_ARGUMENT";
                result.trace_text = "simulation validation failed: empty role_key or perm_key in simulated_bindings";

                return result;
            }

            if(!admin_dao_->roleExists(request.app_code, binding.role_key)) {

                result.allowed = false;
                result.reason = "模拟输入引用了不存在的角色";
                result.deny_code = "NOT_FOUND";
                result.trace_text = "simulation validation failed: role not found in simulated_bindings, role_key = " + binding.role_key;

                return result;
            }

            if(!admin_dao_->permissionExists(request.app_code, binding.perm_key)) {

                result.allowed = false;
                result.reason = "模拟输入引用了不存在的权限";
                result.deny_code = "NOT_FOUND";
                result.trace_text = "simulation validation failed: permission not found in simulated_bindings, perm_key = " + binding.perm_key;

                return result;
            }
        }
        for(const auto& owner_override : request.simulated_owner_overrides) {

            if(owner_override.resource_type.empty() || owner_override.resource_id.empty() || owner_override.owner_user_id.empty()) {

                result.allowed = false;
                result.reason = "模拟输入错误：simulated_owner_overrides 字段不完整";
                result.deny_code = "INVALID_ARGUMENT";
                result.trace_text = "simulation validation failed: invalid simulated_owner_overrides item";

                return result;
            }
            }
        }
    RoleSet effective_roles = buildEffectiveRoles(request, result);

    PermissionSet effective_permissions = buildEffectivePermssions(request, effective_roles, result);

    if(tryOwnerShortcut(request, result)) {

        result.current_roles = roleSetToVector(effective_roles);

        std::ostringstream oss;
        oss << "simulation owner shortcut allowed";

        if(!result.applied_simulations.empty()) {

            oss << ", applied_simulations = [" << joinStrings(result.applied_simulations) << "]";
        }

        oss << ", effective_roles = [" <<joinStrings(result.current_roles) << "]";

        oss << ", policy_version = " << result.policy_version;

        result.trace_text = oss.str();

        return result;
    }

    evaluateByRbac(request, effective_roles, effective_permissions, result);

    return result;
}

// ======================================================
// validateRequest
// 作用：校验模拟请求参数是否合法
// ======================================================
bool SimulationEngine::validateRequest(const SimulationRequest& request, SimulationResult& result) {

    if(request.app_code.empty()) {

        result.allowed = false;
        result.reason = "参数不完整：app_code 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "simulation validation failed: empty app_code";

        return false;
    }

    if(request.user_id.empty()) {

        result.allowed = false;
        result.reason = "参数不完整：user_id 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "simulation validation failed: empty user_id";

        return false;
    }

    if(request.perm_key.empty()) {

        result.allowed = false;
        result.reason = "参数不完整：perm_key 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "simulation validation failed: empty perm_key";

        return false;
    }

    const bool has_resource_type = !request.resource_type.empty();
    const bool has_resource_id = !request.resource_id.empty();

    if(has_resource_type != has_resource_id) {

        result.allowed = false;
        result.reason = "参数不完整：resource_type 和 resource_id 必须同时提供";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "simulation validation failed: resource_type / resource_id mismatch";

        return false;
    }

    return true;
}

// ======================================================
// buildEffectiveRoles
// 作用：构造“模拟后的有效角色集合”
//
// 逻辑：
// 1. 读取用户当前真实角色
// 2. 把 simulated_grants 中属于该用户的角色叠加进去
// ======================================================
SimulationEngine::RoleSet SimulationEngine::buildEffectiveRoles(const SimulationRequest& request, SimulationResult& result) {

    RoleSet effective_roles;

    const std::vector<std::string> real_roles = permission_dao_->getUserRoles(request.app_code, request.user_id);

    for(const auto& role : real_roles) {
       
        effective_roles.insert(role);
    }

    for(const auto& grant : request.simulated_grants) {

        if(grant.user_id != request.user_id) {
            continue;
        }

        const auto insert_result = effective_roles.insert(grant.role_key);

        if(insert_result.second) {

            result.applied_simulations.push_back("simulated grant applied: " + request.user_id + "->" + grant.role_key);
        }
    }

    return effective_roles;
}

// ======================================================
// buildEffectivePermissions
// 作用：构造“模拟后的有效权限集合”
//
// 逻辑：
// 1. 先读取用户当前真实权限
// 2. 再看 simulated_bindings 是否会给当前“有效角色集合”额外增加权限
// ======================================================
SimulationEngine::PermissionSet SimulationEngine::buildEffectivePermssions(const SimulationRequest& request, const RoleSet& effective_roles, SimulationResult& result) {

    PermissionSet effective_permissions;

    const std::vector<std::string> real_permissions = permission_dao_->getUserPermissions(request.app_code, request.user_id);

    for(const auto& perm : real_permissions) {

        effective_permissions.insert(perm);
    }

    for(const auto& binding : request.simulated_bindings){

        if(effective_roles.find(binding.role_key) == effective_roles.end()){
            continue;
        }

        const auto insert_result = effective_permissions.insert(binding.perm_key);

        if(insert_result.second) {

            result.applied_simulations.push_back("simulated binding applied: " + binding.role_key + "->" + binding.perm_key);
        }
    }

    return effective_permissions;
}

// ======================================================
// resolveEffectiveOwner
// 作用：解析“当前模拟上下文中的有效 owner”
//
// 优先级：
// 1. 先看 simulated_owner_overrides
// 2. 没有再查真实数据库里的 owner
// ======================================================
std::optional<std::string> SimulationEngine::resolveEffectiveOwner(const SimulationRequest& request, SimulationResult& result) {

    if(request.resource_type.empty() || request.resource_id.empty()) {
        return std::nullopt;
    }

    auto overrride_owner = findSimulatedOwnerOverride(request);

    if(overrride_owner.has_value()) {

        result.applied_simulations.push_back("simulated owner override applied: " + request.resource_type + "/" + request.resource_id + "->" + overrride_owner.value());

        return overrride_owner;
    }

    return admin_dao_->getResourceOwner(request.app_code, request.resource_type, request.resource_id);
}

// ======================================================
// tryOwnerShortcut
// 作用：尝试走 owner 快捷规则
//
// 返回：
//   true  -> 已经放行，不需要继续走 RBAC
//   false -> 没有通过 owner 规则，继续走 RBAC
// ======================================================
bool SimulationEngine::tryOwnerShortcut(const SimulationRequest& request, SimulationResult& result) {

    if(request.resource_type.empty() || request.resource_id.empty()) {

        return false;
    }

    const bool owner_shortcut_enabled = permission_dao_->isOwnerShortcutEnabled(request.app_code, request.perm_key);

    if(!owner_shortcut_enabled) {

        return false;
    }

    auto owner_opt = resolveEffectiveOwner(request, result);

    if(!owner_opt.has_value()) {
        return false;
    }

    if(owner_opt.value() == request.user_id) {

        result.allowed = true;
        result.reason = "模拟结果：资源 owner 快捷规则允许访问";
        result.deny_code.clear();
        result.owner_shortcut_used = true;
        result.matched_permissions.push_back(request.perm_key);

        return true;
    }

    return false;
}

// ======================================================
// evaluateByRbac
// 作用：执行“模拟版 RBAC 判断”
//
// 这里基于的是：
// - effective_roles
// - effective_permissions
// 而不是纯真实数据
// ======================================================
void SimulationEngine::evaluateByRbac(const SimulationRequest& request, const RoleSet& effective_roles, const PermissionSet& effective_permissions, SimulationResult& result) {

    result.current_roles = roleSetToVector(effective_roles);

    std::vector<std::string> candidate_roles = permission_dao_->getRolesWithPermission(request.app_code, request.perm_key);

    RoleSet candidate_role_set;

    for(const auto& role : candidate_roles) {

        candidate_role_set.insert(role);
    }

    for(const auto& binding : request.simulated_bindings) {

        if(binding.perm_key == request.perm_key) {

            candidate_role_set.insert(binding.role_key);
        }
    }

    candidate_roles = roleSetToVector(candidate_role_set);

    if(effective_roles.empty()) {

        result.allowed = false;
        result.reason = "模拟结果：用户未分配任何角色";
        result.deny_code = "USER_HAS_NO_ROLE";
        result.suggest_roles = candidate_roles;

        std::ostringstream oss;
        
        oss << "simulation rabc denied: no effective roles";
        if(!result.applied_simulations.empty()) {
            oss << ", applied_simulations = [" << joinStrings(result.applied_simulations) << "]";
        }
        oss << ", required_permission = " << request.perm_key;

        result.trace_text = oss.str();

        return ;
    }

    const bool permission_matched = (effective_permissions.find(request.perm_key) != effective_permissions.end());

    if(permission_matched) {

        result.allowed = true;
        result.reason = "模拟结果：角色权限允许访问";
        result.deny_code.clear();
        result.matched_permissions.push_back(request.perm_key);

        for(const auto& role : candidate_roles) {

            if(effective_roles.find(role) != effective_roles.end()) {

                result.matched_roles.push_back(role);
            }
        }

        std::ostringstream oss;

        oss << "simulation rabc allowed"
            << ", effective_roles = [" << joinStrings(result.current_roles) << "]"
            << ", matched_roles = [" << joinStrings(result.matched_roles) << "]"
            << ", perm_key = " << request.perm_key
            << ", source = " << result.decision_source_text;
    
        if(!result.applied_simulations.empty()) {

            oss << ", applied_simulations = [" << joinStrings(result.applied_simulations) << "]";
        }

        result.trace_text = oss.str();

        return ;
    }

    result.allowed = false;
    result.reason = "模拟结果：用户没有权限";
    result.deny_code = "PERMISSION_DENIED";
    result.suggest_roles = candidate_roles;

    std::ostringstream oss;
    oss << "simulation rabc denied"
        << ", effective_roles = [" << joinStrings(result.current_roles) << "]"
        << ", required_permission = " << request.perm_key
        << ", suggest_roles = [" <<joinStrings(result.suggest_roles) << "]"
        << ", source = " << result.decision_source_text;

    if(!result.applied_simulations.empty()) {
        oss << ", applied_simulations = [" << joinStrings(result.applied_simulations) << "]";
    }

    result.trace_text = oss.str();
}

// ======================================================
// hasSimulatedBinding
// 作用：判断某个角色和权限之间，是否存在模拟绑定
// ======================================================
bool SimulationEngine::hasSimulatedBinding(const SimulationRequest& request, const std::string& role_key, const std::string& perm_key) const {

    for(const auto& binding : request.simulated_bindings) {

        if(binding.role_key == role_key && binding.perm_key == perm_key) {
            return true;
        }
    }

    return false;
}

// ======================================================
// hasSimulatedGrant
// 作用：判断某个用户和角色之间，是否存在模拟授予
// ======================================================
bool SimulationEngine::hasSimulatedGrant(const SimulationRequest& request, const std::string& user_id, const std::string& role_key) const {

    for(const auto& grant : request.simulated_grants) {
        if(grant.user_id == user_id && grant.role_key == role_key) {
            return true;
        }
    }

    return false;
}

// ======================================================
// findSimulatedOwnerOverride
// 作用：查找当前请求目标资源是否有模拟 owner override
// ======================================================
std::optional<std::string> SimulationEngine::findSimulatedOwnerOverride(const SimulationRequest& request) const {

    for(const auto& owner_overrride : request.simulated_owner_overrides) {

        if(owner_overrride.resource_type == request.resource_type && owner_overrride.resource_id == request.resource_id) {

            return owner_overrride.owner_user_id;
        }
    }

    return std::nullopt;
}

// ======================================================
// roleSetToVector
// 作用：把角色集合转成有序 vector，便于结果输出更稳定
// ======================================================
std::vector<std::string> SimulationEngine::roleSetToVector(const RoleSet& roles) const {

    std::vector<std::string> result;

    result.reserve(roles.size());

    for(const auto& role : roles) {

        result.push_back(role);
    }

    std::sort(result.begin(), result.end());

    return result;
}

// ======================================================
// permissionSetToVector
// 作用：把权限集合转成有序 vector
// ======================================================
std::vector<std::string> SimulationEngine::permissionSetToVector(const PermissionSet& perms) const {

    std::vector<std::string> result;

    result.reserve(perms.size());

    for(const auto& perm : perms) {

        result.push_back(perm);
    }

    std::sort(result.begin(), result.end());

    return result;
}

// ======================================================
// joinStrings
// 作用：把字符串数组拼成逗号分隔文本
// ======================================================
std::string SimulationEngine::joinStrings(const std::vector<std::string>& items) const {
    
    if(items.empty()){
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