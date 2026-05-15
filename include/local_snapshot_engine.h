#ifndef NY_AUTH_LOCAL_SNAPSHOT_ENGINE_H
#define NY_AUTH_LOCAL_SNAPSHOT_ENGINE_H

// 提供 std::shared_ptr
#include <memory>

// 提供 std::mutex
#include <mutex>

// 提供 std::optional
#include <optional>

// 提供 std::string
#include <string>

// 提供 std::unordered_set
#include <unordered_set>

// 提供 std::vector
#include <vector>

// 引入快照数据结构
#include "snapshot_types.h"

// ======================================================
// LocalSnapshotCheckRequest
// 作用：表示一次“基于本地快照的判权请求”
// ======================================================
struct LocalSnapshotCheckRequest {
    // 所属应用
    std::string app_code;

    // 被判断的用户
    std::string user_id;

    // 目标权限
    std::string perm_key;

    // 资源类型（可选）
    std::string resource_type;

    // 资源 id（可选）
    std::string resource_id;

    // 请求追踪 id
    std::string request_id;
};

// ======================================================
// LocalSnapshotCheckResult
// 作用：表示一次“本地快照判权”的结果
//
// 设计思路：
// - 尽量保留和中心鉴权、模拟鉴权相似的解释能力
// - 但明确说明判权来源是 LOCAL_SNAPSHOT
// ======================================================
struct LocalSnapshotCheckResult {
    // 最终是否允许
    bool allowed = false;

    // 可读原因
    std::string reason;

    // 拒绝码（字符串）
    // 例如：
    // OK
    // SNAPSHOT_NOT_READY
    // APP_NOT_FOUND
    // APP_DISABLED
    // PERMISSION_NOT_FOUND
    // RESOURCE_NOT_FOUND
    // USER_HAS_NO_ROLE
    // PERMISSION_DENIED
    // INVALID_ARGUMENT
    // INTERNAL_ERROR
    std::string deny_code;

    // 当前角色
    std::vector<std::string> current_roles;

    // 建议角色
    std::vector<std::string> suggest_roles;

    // 实际命中的角色
    std::vector<std::string> matched_roles;

    // 实际命中的权限
    std::vector<std::string> matched_permissions;

    // 是否使用了 owner 快捷规则
    bool owner_shortcut_used = false;

    // 本地使用的策略版本
    int policy_version = 1;

    // 本地使用的快照 id
    int64_t snapshot_id = 0;

    // 判权来源文本
    // 当前固定为：LOCAL_SNAPSHOT
    std::string decision_source_text = "LOCAL_SNAPSHOT";

    // 更详细的解释文本
    std::string trace_text;
};

// ======================================================
// LocalSnapshotEngine
// 作用：本地快照判权引擎
//
// 它负责：
// 1. 持有一份当前本地可用的 IndexedPolicySnapshot
// 2. 基于这份快照执行本地判权
// 3. 在中心服务不可用时提供降级能力
//
// 注意：
// - 它不查数据库
// - 它不访问中心 RPC
// - 它只依赖本地快照
// ======================================================
class LocalSnapshotEngine {
public:
    // 角色集合
    using RoleSet = std::unordered_set<std::string>;

    // 权限集合
    using PermissionSet = std::unordered_set<std::string>;

    // 构造函数
    LocalSnapshotEngine();

    // 更新当前本地快照
    // 说明：
    // - 会整体替换旧快照
    // - 成功返回 true
    bool LoadSnapshot(const IndexedPolicySnapshot& indexed_snapshot);

    // 清空当前本地快照
    void ClearSnapshot();

    // 当前是否已有可用快照
    bool HasSnapshot() const;

    // 获取当前快照的 app_code
    std::string CurrentAppCode() const;

    // 获取当前快照的 policy_version
    int CurrentPolicyVersion() const;

    // 获取当前快照的 snapshot_id
    int64_t CurrentSnapshotId() const;

    // 核心方法：基于本地快照执行一次判权
    LocalSnapshotCheckResult Check(const LocalSnapshotCheckRequest& request) const;

private:
    // 校验请求是否合法
    bool validateRequest(const LocalSnapshotCheckRequest& request,
                         LocalSnapshotCheckResult& result) const;

    // 获取当前快照副本
    std::shared_ptr<IndexedPolicySnapshot> getSnapshotCopy() const;

    // 基于快照计算当前用户的有效角色
    RoleSet getUserRoles(const IndexedPolicySnapshot& snapshot,
                         const std::string& user_id) const;

    // 基于角色集合计算有效权限
    PermissionSet getPermissionsByRoles(const IndexedPolicySnapshot& snapshot,
                                        const RoleSet& roles) const;

    // 获取某个资源当前 owner
    std::optional<std::string> getResourceOwner(
        const IndexedPolicySnapshot& snapshot,
        const std::string& resource_type,
        const std::string& resource_id) const;

    // 查询某个权限定义
    const SnapshotPermission* findPermission(
        const IndexedPolicySnapshot& snapshot,
        const std::string& perm_key) const;

    // 获取拥有某个权限的所有角色
    std::vector<std::string> getRolesWithPermission(
        const IndexedPolicySnapshot& snapshot,
        const std::string& perm_key) const;

    // 先尝试 owner 快捷规则
    // 返回 true 表示已经决定放行
    bool tryOwnerShortcut(const IndexedPolicySnapshot& snapshot,
                          const LocalSnapshotCheckRequest& request,
                          LocalSnapshotCheckResult& result) const;

    // 走快照版 RBAC 判断
    void evaluateByRbac(const IndexedPolicySnapshot& snapshot,
                        const LocalSnapshotCheckRequest& request,
                        const RoleSet& roles,
                        const PermissionSet& permissions,
                        LocalSnapshotCheckResult& result) const;

    // 把角色集合转成有序 vector
    std::vector<std::string> roleSetToVector(const RoleSet& roles) const;

    // 把权限集合转成有序 vector
    std::vector<std::string> permissionSetToVector(const PermissionSet& permissions) const;

    // 把字符串数组拼成逗号分隔文本
    std::string joinStrings(const std::vector<std::string>& items) const;

private:
    // 保护 current_snapshot_
    mutable std::mutex snapshot_mutex_;

    // 当前本地快照
    std::shared_ptr<IndexedPolicySnapshot> current_snapshot_;
};

#endif
