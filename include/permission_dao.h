#ifndef NY_AUTH_PERMISSION_DAO_H
#define NY_AUTH_PERMISSION_DAO_H

#include <cstdint>

#include <mutex>

#include <optional>

#include <string>

#include <utility>

#include <vector>

#include <cppconn/connection.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <mysql_driver.h>

// ======================================================
// AppInfo：表示一个应用的基础信息
// 为什么要单独抽结构体？
// 1. app_id
// 2. app_code
// 3. app 是否启用
// 4. 当前策略版本是多少
// ======================================================
struct AppInfo {

    int64_t app_id = 0;

    std::string app_code;

    bool enabled = false;

    int policy_version = 1;
};

// ======================================================
// AppInfo：表示一个应用的基础信息
// ======================================================
struct ResourceInfo {

    int64_t resource_pk = 0;

    std::string resource_type;

    std::string resource_id;

    std::string owner_user_id;

    bool enabled = false;
};

// ======================================================
// PermissionInfo：表示一个权限的基础信息
// ======================================================
struct PermissionInfo {

    int64_t permission_id = 0;

    std::string perm_key;

    std::string resource_type;

    bool owner_shortcut_enabled = false;

    bool enabled = false;
};

// ======================================================
// ResourceInfo：表示一个资源的基础信息
// ======================================================
struct DecisionLogRecord {

    int64_t app_id = 0;

    std::string app_code;

    std::string user_id;

    std::string perm_key;

    std::string resource_type;

    std::string resource_id;

    bool allowed = false;

    std::string decision_source;

    std::string matched_roles_csv;

    std::string matched_permissions_csv;

    bool owner_shortcut_used = false;

    int policy_version = 1;

    std::string deny_code;

    std::string reason;

    std::string trace_text;
};

// ======================================================
// PermissionDAO：数据访问层
// 它只负责和数据库交互，不负责业务流程编排
// ======================================================
class PermissionDAO {
public:

    PermissionDAO(const std::string& host, int port, const std::string& user, const std::string& password, const std::string&database);

    std::optional<AppInfo> getAppInfo(const std::string& app_code);

    std::vector<std::string> getUserPermissions(const std::string& app_code, const std::string& user_id);

    std::vector<std::string> getUserRoles(const std::string& app_code, const std::string& user_id);

    std::vector<std::string> getRolesWithPermission(const std::string& app_code, const std::string& perm_key);

    bool permissionExists(const std::string& app_code, const std::string& perm_key);

    std::optional<PermissionInfo> getPermissionInfo(const std::string& app_code, const std::string& perm_key);

    std::optional<ResourceInfo> getResourceInfo(const std::string& app_code, const std::string& resource_type, const std::string& resource_id);

    bool isResourceOwner(const std::string& app_code, const std::string& resource_type, const std::string& resource_id, const std::string& user_id);

    bool isOwnerShortcutEnabled(const std::string& app_code, const std::string& perm_key);

    int getPolicyVersion(const std::string& app_code);

    std::vector<bool> batchCheckPermissions(const std::string& app_code, const std::vector<std::pair<std::string, std::string>>& items);

    bool insertDecisionLog(const DecisionLogRecord& record);

    bool isConnected() const;

    std::string getLastError() const;

private:

    sql::Connection* createConnection();

    void setLastError(const std::string& error);

private:

    std::string host_;

    int port_;

    std::string user_;

    std::string password_;

    std::string database_;

    mutable std::mutex error_mutex_;

    std::string last_error_;
};

#endif
