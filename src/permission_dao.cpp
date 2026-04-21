#include "permission_dao.h"

#include <memory>

#include <sstream>

// ======================================================
// 构造函数
// 作用：保存数据库连接配置
// ======================================================
PermissionDAO::PermissionDAO(const std::string& host, int port, const std::string& user, const std::string& password, const std::string& database):host_(host), port_(port), user_(user), password_(password), database_(database) { }

// ======================================================
// createConnection
// 作用：创建一个新的 MySQL 连接
// ======================================================
sql::Connection* PermissionDAO::createConnection(){

    sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();

    std::ostringstream oss;
    oss << "tcp://" << host_ << ":" <<port_;

    sql::Connection* conn = driver->connect(oss.str(), user_, password_);

    conn->setSchema(database_);

    return conn;
}

// ======================================================
// setLastError
// 作用：线程安全地记录最近一次错误
// ======================================================
void PermissionDAO::setLastError(const std::string& error) {
    
    std::lock_guard<std::mutex> lock(error_mutex_);

    last_error_ = error;
}

// ======================================================
// getAppInfo
// 作用：查询 app 的基础信息
// ======================================================
std::optional<AppInfo> PermissionDAO::getAppInfo(const std::string& app_code){
    try{
        std::unique_ptr<sql::Connection> conn(createConnection());

        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT a.id AS app_id,"
                "       a.app_code AS app_code,"
                "       a.status AS app_status,"
                "       COALESCE(pv.current_version, 1) AS current_version "
                "FROM ny_apps a "
                "LEFT JOIN ny_policy_versions pv ON pv.app_id = a.id "
                "WHERE a.app_code = ? "
                "LIMIT 1"
            )
        );

        stmt->setString(1, app_code);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());

        if(!rs->next()) {
            return std::nullopt;
        }

        AppInfo info;
        info.app_id = rs->getInt64("app_id");
        info.app_code = rs->getString("app_code");
        info.enabled = (rs->getInt("app_status") == 1);
        info.policy_version = rs->getInt("current_version");

        return info;
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return std::nullopt;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return std::nullopt;
    }
}

// ======================================================
// getUserPermissions
// 作用：查询某个用户在某个 app 下拥有的全部权限 key
//
// 查询路径：
// ny_apps
//   -> ny_user_roles
//   -> ny_roles
//   -> ny_role_permissions
//   -> ny_permissions
//
// 只返回当前启用状态下有效的角色和权限
// ======================================================
std::vector<std::string> PermissionDAO::getUserPermissions(const std::string& app_code, const std::string& user_id){
    std::vector<std::string> result;

    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT DISTINCT p.perm_key "
                "FROM ny_apps a "
                "JOIN ny_user_roles ur ON ur.app_id = a.id "
                "JOIN ny_roles r ON r.id = ur.role_id "
                "JOIN ny_role_permissions rp ON rp.role_id = r.id "
                "JOIN ny_permissions p ON p.id = rp.perm_id "
                "WHERE a.app_code = ? "
                "   AND a.status = 1 "
                "   AND ur.app_user_id = ? "
                "   AND r.status = 1 "
                "   AND p.status = 1 "
                "ORDER BY p.perm_key ASC"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, user_id);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());
        while (rs->next()) {   
            result.push_back(rs->getString("perm_key"));
        } 
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
    } catch (const std::exception& e) {
        setLastError(e.what());
    }

    return result;
}

// ======================================================
// getUserRoles
// 作用：查询某个用户在某个 app 下拥有的全部角色 key
//
// 主要给解释型响应使用，例如 current_roles
// ======================================================
std::vector<std::string> PermissionDAO::getUserRoles(const std::string& app_code, const std::string& user_id) {
    std::vector<std::string> result;

    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT DISTINCT r.role_key "
                "FROM ny_apps a "
                "JOIN ny_user_roles ur ON ur.app_id = a.id "
                "JOIN ny_roles r ON r.id = ur.role_id "
                "WHERE a.app_code = ? "
                "   AND a.status = 1 "
                "   AND ur.app_user_id = ? "
                "   AND r.status = 1 "
                "ORDER BY r.role_key ASC"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, user_id);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());
        while (rs->next()) { 
            result.push_back(rs->getString("role_key"));
        } 
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
    } catch (const std::exception& e) {
        setLastError(e.what());
    }

    return result;
}

// ======================================================
// getRolesWithPermission
// 作用：查询“哪些角色拥有某个权限”
//
// 主要用于拒绝时给 suggest_roles
// ======================================================
std::vector<std::string> PermissionDAO::getRolesWithPermission(const std::string& app_code, const std::string& perm_key) {
    std::vector<std::string> result;

    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT DISTINCT r.role_key "
                "FROM ny_apps a "
                "JOIN ny_roles r ON r.app_id = a.id "
                "JOIN ny_role_permissions rp ON  rp.role_id = r.id "
                "JOIN ny_permissions p ON p.id = rp.perm_id "
                "WHERE a.app_code = ? "
                "   AND a.status = 1 "
                "   AND p.perm_key = ? "
                "   AND r.status = 1 "
                "   AND p.status = 1 "
                "ORDER BY r.role_key ASC"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, perm_key);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());
        while (rs->next()) { 
            result.push_back(rs->getString("role_key"));
        } 
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
    } catch (const std::exception& e) {
        setLastError(e.what());
    }

    return result;
}

// ======================================================
// permissionExists
// 作用：判断某个权限是否在该 app 下存在
//
// 注意：这里同时要求权限状态为启用
// 因为禁用权限对运行时来说也等价于不可用
// ======================================================
bool PermissionDAO::permissionExists(const std::string& app_code, const std::string& perm_key) {
    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT 1 "
                "FROM ny_apps a "
                "JOIN ny_permissions p ON p.app_id = a.id "
                "WHERE a.app_code = ? "
                "   AND a.status = 1 "
                "   AND p.perm_key = ? "
                "   AND p.status = 1 "
                "LIMIT 1"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, perm_key);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());
        return rs->next();
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return false;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return false;
    }
}

// ======================================================
// getResourceInfo
// 作用：查询某个具体资源的信息
//
// 主要用于：
// 1. 判断资源是否存在
// 2. 判断资源是否启用
// 3. 获取 owner_user_id
// ======================================================
std::optional<ResourceInfo> PermissionDAO::getResourceInfo(const std::string& app_code, const std::string& resource_type, const std::string& resource_id) {
    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT r.id, r.resource_type, r.resource_id, "
                "       r.owner_user_id, r.status "
                "FROM ny_apps a "
                "JOIN ny_resources r ON r.app_id = a.id "
                "WHERE a.app_code = ? "
                "   AND a.status = 1 "
                "   AND r.resource_type = ? "
                "   AND r.resource_id = ? "
                "LIMIT 1"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, resource_type);
        stmt->setString(3, resource_id);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());
        
        if(!rs->next()){
            return std::nullopt;
        }

        ResourceInfo info;
        info.resource_pk = rs->getInt64("id");
        info.resource_type = rs->getString("resource_type");
        info.resource_id = rs->getString("resource_id");
        info.owner_user_id = rs->getString("owner_user_id");
        info.enabled = (rs->getInt("status") == 1);

        return info;

    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return std::nullopt;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return std::nullopt;
    }
}

// ======================================================
// isResourceOwner
// 作用：判断某个资源是否属于某个用户
// ======================================================
bool PermissionDAO::isResourceOwner(const std::string& app_code,
                                    const std::string& resource_type,
                                    const std::string& resource_id,
                                    const std::string& user_id) {
    try {
        std::unique_ptr<sql::Connection> conn(createConnection());

        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT 1 "
                "FROM ny_apps a "
                "JOIN ny_resources r ON r.app_id = a.id "
                "WHERE a.app_code = ? "
                "  AND a.status = 1 "
                "  AND r.resource_type = ? "
                "  AND r.resource_id = ? "
                "  AND r.owner_user_id = ? "
                "  AND r.status = 1 "
                "LIMIT 1"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, resource_type);
        stmt->setString(3, resource_id);
        stmt->setString(4, user_id);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());
        return rs->next();
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return false;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return false;
    }
}

// ======================================================
// isOwnerShortcutEnabled
// 作用：判断某个权限是否允许 owner 快捷通过
//
// 这个配置来自 ny_permissions.owner_shortcut_enabled
// 不是代码硬编码
// ======================================================
bool PermissionDAO::isOwnerShortcutEnabled(const std::string& app_code, const std::string& perm_key) {
    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT p.owner_shortcut_enabled "
                "FROM ny_apps a "
                "JOIN ny_permissions p ON p.app_id = a.id "
                "WHERE a.app_code = ? "
                "   AND a.status = 1 "
                "   AND p.perm_key = ? "
                "   AND p.status = 1 "
                "LIMIT 1"
            )
        );

        stmt->setString(1, app_code);
        stmt->setString(2, perm_key);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());

        if(!rs->next()) {
            return false;
        }
        return rs->getInt("owner_shortcut_enabled") == 1;

    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return false;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return false;
    }
}

// ======================================================
// getPolicyVersion
// 作用：查询某个 app 当前的策略版本号
//
// 如果没有记录，保守起见返回 1
// ======================================================
int PermissionDAO::getPolicyVersion(const std::string& app_code) {
    try{
        std::unique_ptr<sql::Connection> conn(createConnection());
        
        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "SELECT COALESCE(pv.current_version, 1) AS current_version "
                "FROM ny_apps a "
                "LEFT JOIN ny_policy_versions pv ON pv.app_id = a.id "
                "WHERE a.app_code = ? "
                "LIMIT 1"
            )
        );

        stmt->setString(1, app_code);

        std::unique_ptr<sql::ResultSet> rs(stmt->executeQuery());

        if(!rs->next()) {
            return 1;
        }
        return rs->getInt("current_version");

    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return 1;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return 1;
    }
}

// ======================================================
// batchCheckPermissions
// 作用：批量权限检查辅助
// 对每个 (user_id, perm_key) 先查全量权限，再判断是否包含
// ======================================================
std::vector<bool> PermissionDAO::batchCheckPermissions(const std::string& app_code, const std::vector<std::pair<std::string, std::string>>& items) {
    std::vector<bool> result;

    result.reserve(items.size());

    for(const auto& item : items){

        const std::string& user_id =item.first;

        const std::string& perm_key = item.second;

        std::vector<std::string> permissions = getUserPermissions(app_code, user_id);

        bool allowed = false;
        
        for(const auto& permission : permissions) {

            if(permission == perm_key) {
                
                allowed = true;

                break;
            }
        }

        result.push_back(allowed);
    }
    return result;
}

// ======================================================
// insertDecisionLog
// 作用：插入一条权限决策日志
//
// 对应表：ny_decision_logs
// ======================================================
bool PermissionDAO::insertDecisionLog(const DecisionLogRecord& record) {
    try{
        std::unique_ptr<sql::Connection> conn(createConnection());

        std::unique_ptr<sql::PreparedStatement> stmt(
            conn->prepareStatement(
                "INSERT INTO ny_decision_logs ("
                "   app_id, app_code, user_id, perm_key, "
                "   resource_type, resource_id, allowed, decision_source, "
                "   matched_roles, matched_permissions, owner_shortcut_used, "
                "   policy_version, deny_code, reason, trace_text "
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
        );

        stmt->setInt64(1, record.app_id);
        stmt->setString(2, record.app_code);
        stmt->setString(3, record.user_id);
        stmt->setString(4, record.perm_key);
        stmt->setString(5, record.resource_type);
        stmt->setString(6, record.resource_id);
        stmt->setInt(7, record.allowed ? 1: 0);
        stmt->setString(8, record.decision_source);
        stmt->setString(9, record.matched_roles_csv);
        stmt->setString(10, record.matched_permissions_csv);
        stmt->setInt(11, record.owner_shortcut_used ? 1 : 0);
        stmt->setInt(12, record.policy_version);
        stmt->setString(13, record.deny_code);
        stmt->setString(14, record.reason);
        stmt->setString(15, record.trace_text);

        return stmt->executeUpdate() > 0;
    } catch (const sql::SQLException& e) {
        setLastError(e.what());
        return false;
    } catch (const std::exception& e) {
        setLastError(e.what());
        return false;
    }
}

// ======================================================
// isConnected
// 作用：检查数据库当前是否可连通
// ======================================================
bool PermissionDAO::isConnected() const {
    try{
        std::unique_ptr<sql::Connection> conn(const_cast<PermissionDAO*>(this)->createConnection());

        return conn != nullptr;
    } catch (const sql::SQLException& e) {
        const_cast<PermissionDAO*>(this)->setLastError(e.what());
        return false;
    } catch (const std::exception& e) {
        const_cast<PermissionDAO*>(this)->setLastError(e.what());
        return false;
    }
}

// ======================================================
// isConnected
// 作用：检查数据库当前是否可连通
// ======================================================
std::string PermissionDAO::getLastError() const {

    std::lock_guard<std::mutex> lock(error_mutex_);
    
    return last_error_;
}