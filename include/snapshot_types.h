#ifndef NY_AUTH_SNAPSHOT_TYPES_H
#define NY_AUTH_SNAPSHOT_TYPES_H

// 提供 int64_t
#include <cstdint>

// 提供 std::string
#include <string>

// 提供 std::unordered_map
#include <unordered_map>

// 提供 std::unordered_set
#include <unordered_set>

// 提供 std::vector
#include <vector>

// ======================================================
// SnapshotAppInfo
// 作用：表示快照里的应用基础信息
// ======================================================
struct SnapshotAppInfo {
    // 应用主键 id
    int64_t app_id = 0;

    // 应用编码，例如 doc_center
    std::string app_code;

    // 是否启用
    bool enabled = false;

    // 当前策略版本
    int policy_version = 1;
};

// ======================================================
// SnapshotRole
// 作用：表示快照中的一条角色定义
// ======================================================
struct SnapshotRole {
    // 角色主键 id
    int64_t role_id = 0;

    // 角色 key，例如 editor
    std::string role_key;

    // 角色显示名，例如 编辑者
    std::string role_name;

    // 描述
    std::string description;

    // 是否默认角色
    bool is_default = false;

    // 是否启用
    bool enabled = false;
};

// ======================================================
// SnapshotPermission
// 作用：表示快照中的一条权限定义
// ======================================================
struct SnapshotPermission {
    // 权限主键 id
    int64_t permission_id = 0;

    // 权限 key，例如 document:edit
    std::string perm_key;

    // 权限显示名，例如 编辑文档
    std::string perm_name;

    // 资源类型，例如 document / course / system
    std::string resource_type;

    // 是否支持 owner 快捷规则
    bool owner_shortcut_enabled = false;

    // 描述
    std::string description;

    // 是否启用
    bool enabled = false;
};

// ======================================================
// SnapshotRolePermissionBinding
// 作用：表示一条角色-权限绑定关系
// 例如：editor -> document:edit
// ======================================================
struct SnapshotRolePermissionBinding {
    // 角色 key
    std::string role_key;

    // 权限 key
    std::string perm_key;
};

// ======================================================
// SnapshotUserRoleBinding
// 作用：表示一条用户-角色绑定关系
// 例如：u1002 -> viewer
// ======================================================
struct SnapshotUserRoleBinding {
    // 用户 id
    std::string user_id;

    // 角色 key
    std::string role_key;

    // 授权人（可选，用于调试/审计）
    std::string granted_by;
};

// ======================================================
// SnapshotResourceOwner
// 作用：表示一条资源 owner 信息
// 例如：document/doc_004 -> u3001
// ======================================================
struct SnapshotResourceOwner {
    // 资源类型
    std::string resource_type;

    // 资源 id
    std::string resource_id;

    // 资源名称
    std::string resource_name;

    // owner 用户 id
    std::string owner_user_id;

    // 是否启用
    bool enabled = false;

    // 扩展信息（原始文本）
    std::string metadata_text;
};

// ======================================================
// SnapshotMeta
// 作用：表示快照本身的元信息
// ======================================================
struct SnapshotMeta {
    // 快照表主键 id
    int64_t snapshot_id = 0;

    // 发布人
    std::string published_by;

    // 发布说明
    std::string publish_note;

    // 创建时间（字符串形式）
    std::string created_at;
};

// ======================================================
// PolicySnapshot
// 作用：表示“一整份策略快照”
//
// 这是快照体系最核心的数据结构。
// 后面：
// - SnapshotBuilder 负责构造它
// - SnapshotDAO 负责读写它
// - LocalSnapshotEngine 负责消费它
// ======================================================
struct PolicySnapshot {
    // 应用基础信息
    SnapshotAppInfo app_info;

    // 快照元信息
    SnapshotMeta meta;

    // 角色定义列表
    std::vector<SnapshotRole> roles;

    // 权限定义列表
    std::vector<SnapshotPermission> permissions;

    // 角色-权限绑定列表
    std::vector<SnapshotRolePermissionBinding> role_permission_bindings;

    // 用户-角色绑定列表
    std::vector<SnapshotUserRoleBinding> user_role_bindings;

    // 资源 owner 列表
    std::vector<SnapshotResourceOwner> resource_owners;
};

// ======================================================
// IndexedPolicySnapshot
// 作用：表示“为本地快速判权而建立过索引的快照”
//
// PolicySnapshot 更适合：
// - 构建
// - 序列化
// - 调试
//
// IndexedPolicySnapshot 更适合：
// - 高频本地判权
//
// 也就是说：
// PolicySnapshot 是“原始结构化快照”
// IndexedPolicySnapshot 是“本地判权友好结构”
// ======================================================
struct IndexedPolicySnapshot {
    // 原始快照
    PolicySnapshot snapshot;

    // --------------------------------------------------
    // 下面这些索引，是为了让 LocalSnapshotEngine 快速查找
    // --------------------------------------------------

    // user_id -> 角色集合
    std::unordered_map<std::string, std::unordered_set<std::string>> user_to_roles;

    // role_key -> 权限集合
    std::unordered_map<std::string, std::unordered_set<std::string>> role_to_permissions;

    // perm_key -> 权限定义
    std::unordered_map<std::string, SnapshotPermission> perm_key_to_permission;

    // role_key -> 角色定义
    std::unordered_map<std::string, SnapshotRole> role_key_to_role;

    // resource_key -> owner_user_id
    // resource_key 规则：resource_type + ":" + resource_id
    std::unordered_map<std::string, std::string> resource_to_owner;

    // resource_key -> 资源完整信息
    std::unordered_map<std::string, SnapshotResourceOwner> resource_to_detail;
};

// ======================================================
// BuildSnapshotResourceKey
// 作用：统一生成快照里的资源 key
// 例如：document:doc_004
// ======================================================
inline std::string BuildSnapshotResourceKey(const std::string& resource_type,
                                            const std::string& resource_id) {
    return resource_type + ":" + resource_id;
}

#endif
