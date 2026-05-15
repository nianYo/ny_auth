#include "local_snapshot_engine.h"

#include <algorithm>
#include <sstream>
#include <utility>

// ======================================================
// 构造函数
// 作用：初始化为空快照状态
// ======================================================
LocalSnapshotEngine::LocalSnapshotEngine() = default;

// ======================================================
// LoadSnapshot
// 作用：加载一份新的本地快照，并整体替换旧快照
//
// 说明：
// 1. 当前设计是“整份替换”
// 2. 这样最简单，也最符合快照语义
// 3. 如果传进来的快照 app_code 为空，认为无效
// ======================================================
bool LocalSnapshotEngine::LoadSnapshot(
    const IndexedPolicySnapshot& indexed_snapshot) {
    // 基础校验：快照至少得知道自己属于哪个 app
    if (indexed_snapshot.snapshot.app_info.app_code.empty()) {
        return false;
    }

    // 用 shared_ptr 承载当前快照，方便后续高频读取时少拷贝
    auto new_snapshot = std::make_shared<IndexedPolicySnapshot>(indexed_snapshot);

    // 加锁替换
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    current_snapshot_ = std::move(new_snapshot);

    return true;
}

// ======================================================
// ClearSnapshot
// 作用：清空当前本地快照
// 用途：
// - 测试“无快照”场景
// - 故障恢复时重置
// - 手工切换状态
// ======================================================
void LocalSnapshotEngine::ClearSnapshot() {
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    current_snapshot_.reset();
}

// ======================================================
// HasSnapshot
// 作用：当前是否已有可用快照
// ======================================================
bool LocalSnapshotEngine::HasSnapshot() const {
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    return current_snapshot_ != nullptr;
}

// ======================================================
// CurrentAppCode
// 作用：返回当前快照所属 app_code
// 没有快照时返回空字符串
// ======================================================
std::string LocalSnapshotEngine::CurrentAppCode() const {
    auto snapshot = getSnapshotCopy();
    if (!snapshot) {
        return "";
    }

    return snapshot->snapshot.app_info.app_code;
}

// ======================================================
// CurrentPolicyVersion
// 作用：返回当前快照策略版本
// 没有快照时返回 0
// ======================================================
int LocalSnapshotEngine::CurrentPolicyVersion() const {
    auto snapshot = getSnapshotCopy();
    if (!snapshot) {
        return 0;
    }

    return snapshot->snapshot.app_info.policy_version;
}

// ======================================================
// CurrentSnapshotId
// 作用：返回当前快照 id
// 没有快照时返回 0
// ======================================================
int64_t LocalSnapshotEngine::CurrentSnapshotId() const {
    auto snapshot = getSnapshotCopy();
    if (!snapshot) {
        return 0;
    }

    return snapshot->snapshot.meta.snapshot_id;
}

// ======================================================
// Check
// 作用：基于当前本地快照执行一次本地判权
//
// 流程：
// 1. 校验请求结构
// 2. 校验本地是否已有快照
// 3. 校验 app 是否匹配、是否启用
// 4. 校验目标权限是否存在且启用
// 5. 如果带资源，校验资源是否存在且启用
// 6. 获取用户有效角色
// 7. 获取角色对应的有效权限
// 8. 先尝试 owner 快捷规则
// 9. 再走 RBAC 判断
// ======================================================
LocalSnapshotCheckResult LocalSnapshotEngine::Check(
    const LocalSnapshotCheckRequest& request) const {
    LocalSnapshotCheckResult result;

    // 1) 先做基础参数校验
    if (!validateRequest(request, result)) {
        return result;
    }

    // 2) 取当前快照副本
    auto snapshot_ptr = getSnapshotCopy();
    if (!snapshot_ptr) {
        result.allowed = false;
        result.reason = "本地快照尚未准备好";
        result.deny_code = "SNAPSHOT_NOT_READY";
        result.trace_text = "local snapshot check failed: no snapshot loaded";
        return result;
    }

    const IndexedPolicySnapshot& snapshot = *snapshot_ptr;

    // 回填当前快照版本信息
    result.policy_version = snapshot.snapshot.app_info.policy_version;
    result.snapshot_id = snapshot.snapshot.meta.snapshot_id;

    // 3) 校验 app 是否匹配
    if (snapshot.snapshot.app_info.app_code != request.app_code) {
        result.allowed = false;
        result.reason = "应用不存在";
        result.deny_code = "APP_NOT_FOUND";
        result.trace_text =
            "local snapshot check failed: app mismatch, request_app=" +
            request.app_code + ", snapshot_app=" +
            snapshot.snapshot.app_info.app_code;
        return result;
    }

    // 4) 校验 app 是否启用
    if (!snapshot.snapshot.app_info.enabled) {
        result.allowed = false;
        result.reason = "应用已被禁用";
        result.deny_code = "APP_DISABLED";
        result.trace_text =
            "local snapshot check failed: app disabled, app_code=" +
            request.app_code;
        return result;
    }

    // 5) 校验权限是否存在且启用
    const SnapshotPermission* permission =
        findPermission(snapshot, request.perm_key);
    if (permission == nullptr) {
        result.allowed = false;
        result.reason = "权限不存在";
        result.deny_code = "PERMISSION_NOT_FOUND";
        result.trace_text =
            "local snapshot check failed: permission not found, perm_key=" +
            request.perm_key;
        return result;
    }

    // 6) 如果带资源，则校验资源是否存在且启用
    if (!request.resource_type.empty() && !request.resource_id.empty()) {
        if (!permission->resource_type.empty() &&
            permission->resource_type != request.resource_type) {
            result.allowed = false;
            result.reason = "权限不适用于该资源类型";
            result.deny_code = "PERMISSION_DENIED";
            result.trace_text =
                "local snapshot check failed: permission resource_type mismatch, perm_key=" +
                request.perm_key + ", permission_resource_type=" +
                permission->resource_type + ", request_resource_type=" +
                request.resource_type;
            return result;
        }

        const std::string resource_key =
            BuildSnapshotResourceKey(request.resource_type, request.resource_id);

        const auto detail_it = snapshot.resource_to_detail.find(resource_key);
        if (detail_it == snapshot.resource_to_detail.end()) {
            result.allowed = false;
            result.reason = "资源不存在";
            result.deny_code = "RESOURCE_NOT_FOUND";
            result.trace_text =
                "local snapshot check failed: resource not found, resource_key=" +
                resource_key;
            return result;
        }

        if (!detail_it->second.enabled) {
            result.allowed = false;
            result.reason = "资源不存在或已禁用";
            result.deny_code = "RESOURCE_NOT_FOUND";
            result.trace_text =
                "local snapshot check failed: resource disabled, resource_key=" +
                resource_key;
            return result;
        }
    }

    // 7) 计算当前用户有效角色
    RoleSet roles = getUserRoles(snapshot, request.user_id);
    result.current_roles = roleSetToVector(roles);

    // 8) 计算有效权限集合
    PermissionSet permissions = getPermissionsByRoles(snapshot, roles);

    // 9) 先尝试 owner 快捷规则
    if (tryOwnerShortcut(snapshot, request, result)) {
        std::ostringstream oss;
        oss << "local snapshot owner shortcut allowed"
            << ", app_code=" << request.app_code
            << ", user_id=" << request.user_id
            << ", perm_key=" << request.perm_key
            << ", current_roles=[" << joinStrings(result.current_roles) << "]"
            << ", snapshot_id=" << result.snapshot_id
            << ", policy_version=" << result.policy_version
            << ", source=" << result.decision_source_text;
        result.trace_text = oss.str();
        return result;
    }

    // 10) owner 没放行，则走 RBAC
    evaluateByRbac(snapshot, request, roles, permissions, result);
    return result;
}

// ======================================================
// validateRequest
// 作用：校验请求参数是否合法
// ======================================================
bool LocalSnapshotEngine::validateRequest(
    const LocalSnapshotCheckRequest& request,
    LocalSnapshotCheckResult& result) const {
    if (request.app_code.empty()) {
        result.allowed = false;
        result.reason = "参数不完整：app_code 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "local snapshot validation failed: empty app_code";
        return false;
    }

    if (request.user_id.empty()) {
        result.allowed = false;
        result.reason = "参数不完整：user_id 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "local snapshot validation failed: empty user_id";
        return false;
    }

    if (request.perm_key.empty()) {
        result.allowed = false;
        result.reason = "参数不完整：perm_key 不能为空";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text = "local snapshot validation failed: empty perm_key";
        return false;
    }

    const bool has_resource_type = !request.resource_type.empty();
    const bool has_resource_id = !request.resource_id.empty();

    // resource_type 和 resource_id 必须同时为空或同时非空
    if (has_resource_type != has_resource_id) {
        result.allowed = false;
        result.reason = "参数不完整：resource_type 和 resource_id 必须同时提供";
        result.deny_code = "INVALID_ARGUMENT";
        result.trace_text =
            "local snapshot validation failed: resource_type/resource_id mismatch";
        return false;
    }

    return true;
}

// ======================================================
// getSnapshotCopy
// 作用：线程安全地取当前快照 shared_ptr 副本
//
// 这样做的好处：
// 1. 锁只持有很短时间
// 2. 锁外仍可安全使用快照对象
// ======================================================
std::shared_ptr<IndexedPolicySnapshot> LocalSnapshotEngine::getSnapshotCopy() const {
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    return current_snapshot_;
}

// ======================================================
// getUserRoles
// 作用：从快照里取当前用户有效角色
//
// 规则：
// 1. 从 user_to_roles 里查用户角色集合
// 2. 只保留“角色定义存在且 enabled=true”的角色
// ======================================================
LocalSnapshotEngine::RoleSet LocalSnapshotEngine::getUserRoles(
    const IndexedPolicySnapshot& snapshot,
    const std::string& user_id) const {
    RoleSet roles;

    const auto it = snapshot.user_to_roles.find(user_id);
    if (it == snapshot.user_to_roles.end()) {
        return roles;
    }

    for (const auto& role_key : it->second) {
        const auto role_it = snapshot.role_key_to_role.find(role_key);
        if (role_it == snapshot.role_key_to_role.end()) {
            continue;
        }

        if (!role_it->second.enabled) {
            continue;
        }

        roles.insert(role_key);
    }

    return roles;
}

// ======================================================
// getPermissionsByRoles
// 作用：根据角色集合计算有效权限集合
//
// 规则：
// 1. 遍历所有有效角色
// 2. 看每个角色绑定了哪些权限
// 3. 只保留“权限定义存在且 enabled=true”的权限
// ======================================================
LocalSnapshotEngine::PermissionSet LocalSnapshotEngine::getPermissionsByRoles(
    const IndexedPolicySnapshot& snapshot,
    const RoleSet& roles) const {
    PermissionSet permissions;

    for (const auto& role_key : roles) {
        const auto rp_it = snapshot.role_to_permissions.find(role_key);
        if (rp_it == snapshot.role_to_permissions.end()) {
            continue;
        }

        for (const auto& perm_key : rp_it->second) {
            const auto perm_it = snapshot.perm_key_to_permission.find(perm_key);
            if (perm_it == snapshot.perm_key_to_permission.end()) {
                continue;
            }

            if (!perm_it->second.enabled) {
                continue;
            }

            permissions.insert(perm_key);
        }
    }

    return permissions;
}

// ======================================================
// getResourceOwner
// 作用：查询某个资源当前 owner
//
// 返回：
// - 查到 -> owner_user_id
// - 查不到 / 资源禁用 -> std::nullopt
// ======================================================
std::optional<std::string> LocalSnapshotEngine::getResourceOwner(
    const IndexedPolicySnapshot& snapshot,
    const std::string& resource_type,
    const std::string& resource_id) const {
    const std::string resource_key =
        BuildSnapshotResourceKey(resource_type, resource_id);

    const auto it = snapshot.resource_to_detail.find(resource_key);
    if (it == snapshot.resource_to_detail.end()) {
        return std::nullopt;
    }

    if (!it->second.enabled) {
        return std::nullopt;
    }

    return it->second.owner_user_id;
}

// ======================================================
// findPermission
// 作用：查某个权限定义
//
// 规则：
// - 权限不存在 -> nullptr
// - 权限存在但 disabled -> nullptr
// ======================================================
const SnapshotPermission* LocalSnapshotEngine::findPermission(
    const IndexedPolicySnapshot& snapshot,
    const std::string& perm_key) const {
    const auto it = snapshot.perm_key_to_permission.find(perm_key);
    if (it == snapshot.perm_key_to_permission.end()) {
        return nullptr;
    }

    if (!it->second.enabled) {
        return nullptr;
    }

    return &(it->second);
}

// ======================================================
// getRolesWithPermission
// 作用：反向查询“哪些角色拥有某个权限”
//
// 用途：
// 1. suggest_roles
// 2. matched_roles
//
// 规则：
// - 只返回 enabled 角色
// - 权限定义本身也必须存在且 enabled
// ======================================================
std::vector<std::string> LocalSnapshotEngine::getRolesWithPermission(
    const IndexedPolicySnapshot& snapshot,
    const std::string& perm_key) const {
    std::vector<std::string> roles;

    const SnapshotPermission* permission = findPermission(snapshot, perm_key);
    if (permission == nullptr) {
        return roles;
    }

    for (const auto& pair : snapshot.role_to_permissions) {
        const std::string& role_key = pair.first;
        const auto& perm_set = pair.second;

        if (perm_set.find(perm_key) == perm_set.end()) {
            continue;
        }

        const auto role_it = snapshot.role_key_to_role.find(role_key);
        if (role_it == snapshot.role_key_to_role.end()) {
            continue;
        }

        if (!role_it->second.enabled) {
            continue;
        }

        roles.push_back(role_key);
    }

    std::sort(roles.begin(), roles.end());
    return roles;
}

// ======================================================
// tryOwnerShortcut
// 作用：尝试走 owner 快捷规则
//
// 返回：
// - true  -> 已经决定放行
// - false -> 没有通过 owner 规则，继续走 RBAC
// ======================================================
bool LocalSnapshotEngine::tryOwnerShortcut(
    const IndexedPolicySnapshot& snapshot,
    const LocalSnapshotCheckRequest& request,
    LocalSnapshotCheckResult& result) const {
    // 没有资源，就不可能走 owner 规则
    if (request.resource_type.empty() || request.resource_id.empty()) {
        return false;
    }

    // 查权限定义
    const SnapshotPermission* permission =
        findPermission(snapshot, request.perm_key);
    if (permission == nullptr) {
        return false;
    }

    // 该权限没开启 owner 快捷规则
    if (!permission->owner_shortcut_enabled) {
        return false;
    }

    // 查资源 owner
    auto owner_opt = getResourceOwner(
        snapshot,
        request.resource_type,
        request.resource_id
    );
    if (!owner_opt.has_value()) {
        return false;
    }

    // owner 命中则直接放行
    if (owner_opt.value() == request.user_id) {
        result.allowed = true;
        result.reason = "本地快照结果：资源 owner 快捷规则允许访问";
        result.deny_code = "OK";
        result.owner_shortcut_used = true;
        result.matched_permissions.push_back(request.perm_key);
        return true;
    }

    return false;
}

// ======================================================
// evaluateByRbac
// 作用：执行“快照版 RBAC 判断”
//
// 规则：
// 1. 如果没有角色 -> USER_HAS_NO_ROLE
// 2. 如果有角色且权限命中 -> allow
// 3. 如果有角色但权限没命中 -> PERMISSION_DENIED
// ======================================================
void LocalSnapshotEngine::evaluateByRbac(
    const IndexedPolicySnapshot& snapshot,
    const LocalSnapshotCheckRequest& request,
    const RoleSet& roles,
    const PermissionSet& permissions,
    LocalSnapshotCheckResult& result) const {
    // 先准备候选角色（哪些角色拥有该权限）
    std::vector<std::string> candidate_roles =
        getRolesWithPermission(snapshot, request.perm_key);

    // 没有任何角色
    if (roles.empty()) {
        result.allowed = false;
        result.reason = "本地快照结果：用户未分配任何角色";
        result.deny_code = "USER_HAS_NO_ROLE";
        result.suggest_roles = candidate_roles;

        std::ostringstream oss;
        oss << "local snapshot rbac denied: no roles"
            << ", user_id=" << request.user_id
            << ", perm_key=" << request.perm_key
            << ", suggest_roles=[" << joinStrings(result.suggest_roles) << "]"
            << ", snapshot_id=" << result.snapshot_id
            << ", policy_version=" << result.policy_version
            << ", source=" << result.decision_source_text;
        result.trace_text = oss.str();
        return;
    }

    // 判断目标权限是否命中
    const bool permission_matched =
        (permissions.find(request.perm_key) != permissions.end());

    if (permission_matched) {
        result.allowed = true;
        result.reason = "本地快照结果：角色权限允许访问";
        result.deny_code = "OK";
        result.matched_permissions.push_back(request.perm_key);

        // 命中的角色 = 当前角色 ∩ 候选角色
        for (const auto& role_key : candidate_roles) {
            if (roles.find(role_key) != roles.end()) {
                result.matched_roles.push_back(role_key);
            }
        }

        std::ostringstream oss;
        oss << "local snapshot rbac allowed"
            << ", user_id=" << request.user_id
            << ", perm_key=" << request.perm_key
            << ", current_roles=[" << joinStrings(result.current_roles) << "]"
            << ", matched_roles=[" << joinStrings(result.matched_roles) << "]"
            << ", matched_permissions=[" << joinStrings(result.matched_permissions) << "]"
            << ", snapshot_id=" << result.snapshot_id
            << ", policy_version=" << result.policy_version
            << ", source=" << result.decision_source_text;
        result.trace_text = oss.str();
        return;
    }

    // 有角色，但没有该权限
    result.allowed = false;
    result.reason = "本地快照结果：用户没有该权限";
    result.deny_code = "PERMISSION_DENIED";
    result.suggest_roles = candidate_roles;

    std::ostringstream oss;
    oss << "local snapshot rbac denied"
        << ", user_id=" << request.user_id
        << ", perm_key=" << request.perm_key
        << ", current_roles=[" << joinStrings(result.current_roles) << "]"
        << ", suggest_roles=[" << joinStrings(result.suggest_roles) << "]"
        << ", snapshot_id=" << result.snapshot_id
        << ", policy_version=" << result.policy_version
        << ", source=" << result.decision_source_text;
    result.trace_text = oss.str();
}

// ======================================================
// roleSetToVector
// 作用：把角色集合转成有序 vector
// ======================================================
std::vector<std::string> LocalSnapshotEngine::roleSetToVector(
    const RoleSet& roles) const {
    std::vector<std::string> result;
    result.reserve(roles.size());

    for (const auto& role : roles) {
        result.push_back(role);
    }

    std::sort(result.begin(), result.end());
    return result;
}

// ======================================================
// permissionSetToVector
// 作用：把权限集合转成有序 vector
// 当前这版虽然主流程没有强依赖它，
// 但保留它很适合后面扩展 trace / 调试输出
// ======================================================
std::vector<std::string> LocalSnapshotEngine::permissionSetToVector(
    const PermissionSet& permissions) const {
    std::vector<std::string> result;
    result.reserve(permissions.size());

    for (const auto& perm : permissions) {
        result.push_back(perm);
    }

    std::sort(result.begin(), result.end());
    return result;
}

// ======================================================
// joinStrings
// 作用：把字符串数组拼成逗号分隔文本
// ======================================================
std::string LocalSnapshotEngine::joinStrings(
    const std::vector<std::string>& items) const {
    if (items.empty()) {
        return "";
    }

    std::ostringstream oss;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << items[i];
    }

    return oss.str();
}
