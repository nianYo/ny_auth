#ifndef NY_AUTH_ADMIN_MANAGER_H
#define NY_AUTH_ADMIN_MANAGER_H

#include <cstdint>

#include <memory>

#include <optional>

#include <string>

#include <vector>

#include "local_cache.h"

#include "session_types.h"

#include "admin_dao.h"

#include "simulation_engine.h"

#include "snapshot_builder.h"

// ======================================================
// AdminOperationStatus
// 作用：统一表示管理操作结果状态
// ======================================================
struct AdminOperationStatus {

    bool success = false;

    std::string message;

    std::string error_code;
};

// ======================================================
// 登录相关
// ======================================================
struct ManagerLoginRequest {

    std::string username;

    std::string password;
};

struct ManagerLoginResult {

    AdminOperationStatus status;

    AdminSessionInfo session;

    int expires_in_seconds = 0;
};

// ======================================================
// 创建角色
// ======================================================
struct ManagerCreateRoleRequest {

    std::string operator_token;

    std::string app_code;

    std::string role_key;

    std::string role_name;

    std::string description;

    bool is_default = false;
};

struct ManagerCreateRoleResult {
    
    AdminOperationStatus status;

    int64_t role_id = 0;
};


// ======================================================
// 创建权限
// ======================================================
struct ManagerCreatePermissionRequest {

    std::string operator_token;

    std::string app_code;

    std::string perm_key;

    std::string perm_name;

    std::string resource_type;

    bool owner_shortcut_enabled = false;

    std::string description;
};

struct ManagerCreatePermissionResult {

    AdminOperationStatus status;

    int64_t permission_id = 0;
};

// ======================================================
// 绑定角色权限
// ======================================================
struct ManagerBindPermissionToRoleRequest {

    std::string operator_token;

    std::string app_code;

    std::string role_key;

    std::string perm_key;
};

struct ManagerBindPermissionToRoleResult {

    AdminOperationStatus status;
};

// ======================================================
// 给用户授角色
// ======================================================
struct ManagerGrantRoleToUserRequest {

    std::string operator_token;

    std::string app_code;

    std::string user_id;

    std::string role_key;
};

struct ManagerGrantRoleToUserResult {

    AdminOperationStatus status;
};

// ======================================================
// 设置资源 owner
// ======================================================
struct ManagerSetResourceOwnerRequest {

    std::string operator_token;

    std::string app_code;

    std::string resource_type;

    std::string resource_id;

    std::string resource_name;

    std::string owner_user_id;

    std::string metadata_text;
};

struct ManagerSetResourceOwnerResult {

    AdminOperationStatus status;
};

// ======================================================
// 发布策略
// ======================================================
struct ManagerPublishPolicyRequest {

    std::string operator_token;

    std::string app_code;

    std::string publish_note;
};

struct ManagerPublishPolicyResult {

    AdminOperationStatus status;

    int new_policy_version = 0;
};

// ======================================================
// 模拟检查
// ======================================================
struct ManagerSimulateCheckRequest {

    std::string operator_token;

    SimulationRequest simulation_request;
};

struct ManagerSimulateCheckResult {

    AdminOperationStatus status;

    SimulationResult simulation_result;
};

// ======================================================
// 查询审计日志
// ======================================================
struct ManagerListAuditLogsRequest {

    std::string operator_token;

    std::string app_code;

    std::string action_type;

    int limit = 20;
};

struct ManagerListAuditLogsResult {

    AdminOperationStatus status;

    std::vector<AuditLogItem> items;
};

// ======================================================
// AdminManager
// 作用：管理端业务逻辑层
//
// 它负责：
// 1. 登录
// 2. token 鉴权
// 3. 创建角色 / 权限
// 4. 绑定关系 / 授角色
// 5. 设置资源 owner
// 6. 发布策略
// 7. 写审计日志
// 8. 调用模拟引擎
// ======================================================
class AdminManager {
public:

    using SessionCache = LocalCache<AdminSessionInfo>;

    AdminManager(std::shared_ptr<AdminDAO> admin_dao, std::shared_ptr<SimulationEngine> simulation_engine, std::shared_ptr<SessionCache> session_cache, int session_ttl_seconds);

    AdminManager(std::shared_ptr<AdminDAO> admin_dao, std::shared_ptr<SimulationEngine> simulation_engine, std::shared_ptr<SessionCache> session_cache, int session_ttl_seconds, std::shared_ptr<SnapshotBuilder> snapshot_builder);

    ManagerLoginResult Login(const ManagerLoginRequest& request);

    ManagerCreateRoleResult CreateRole(const ManagerCreateRoleRequest& request);

    ManagerCreatePermissionResult CreatePermission(const ManagerCreatePermissionRequest& request);

    ManagerBindPermissionToRoleResult BindPermissionToRole(const ManagerBindPermissionToRoleRequest& request);

    ManagerGrantRoleToUserResult GrantRoleToUser(const ManagerGrantRoleToUserRequest& request);

    ManagerSetResourceOwnerResult SetResourceOwner(const ManagerSetResourceOwnerRequest& request);

    ManagerPublishPolicyResult PublishPolicy(const ManagerPublishPolicyRequest& request);

    ManagerSimulateCheckResult SimulateCheck(const ManagerSimulateCheckRequest& request);

    ManagerListAuditLogsResult ListAuditLogs(const ManagerListAuditLogsRequest& request);

private:

    std::optional<OperatorIdentity> authenticateOperator(const std::string& operator_token);

    bool authorizeOperator(const OperatorIdentity& operator_identity) const;

    std::string generateToken(const ConsoleUserInfo& console_user) const;

    AdminSessionInfo buildSession(const ConsoleUserInfo& console_user, const std::string& token) const;

    OperatorIdentity buildOperatorIdentity(const AdminSessionInfo& session_info) const;

    bool writeAuditLog(const OperatorIdentity& operator_identity, const std::string& app_code, const std::string& action_type, const std::string& target_type, const std::string& target_key, const std::string& before_text, const std::string& after_text, const std::string& trace_text);

    int64_t nowUnixSeconds() const;

private:

    std::shared_ptr<AdminDAO> admin_dao_;

    std::shared_ptr<SimulationEngine> simulation_engine_;

    std::shared_ptr<SnapshotBuilder> snapshot_builder_;

    std::shared_ptr<SessionCache> session_cache_;

    int session_ttl_seconds_ = 3600;
};

#endif
