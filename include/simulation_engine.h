#ifndef NY_AUTH_SIMULATION_ENGINE_H
#define NY_AUTH_SIMULATION_ENGINE_H

#include <memory>

#include <optional>

#include <string>

#include <unordered_set>

#include <vector>

#include "permission_dao.h"

#include "admin_dao.h"

// ======================================================
// SimulatedGrantRole
// 作用：表示“一条临时授予角色”的模拟输入
// 例如：给用户 u1002 临时增加 editor 角色
// ======================================================
struct SimulatedGrantRole {

    std::string user_id;

    std::string role_key;
};

// ======================================================
// SimulatedBindPermission
// 作用：表示“一条临时绑定权限”的模拟输入
// 例如：给 viewer 角色临时增加 document:edit 权限
// ======================================================
struct SimulateBindPermission {

    std::string role_key;

    std::string perm_key;
};

// ======================================================
// SimulatedOwnerOverride
// 作用：表示“一条临时 owner 改写”的模拟输入
// 例如：把 document/doc_004 的 owner 临时改成 u3001
// ======================================================
struct SimulatedOwnerOverride{

    std::string resource_type;

    std::string resource_id;

    std::string owner_user_id;
};

// ======================================================
// SimulationRequest
// 作用：表示一次完整的模拟检查请求
// ======================================================
struct SimulationRequest {

    std::string app_code;

    std::string user_id;

    std::string perm_key;

    std::string resource_type;

    std::string resource_id;

    std::string request_id;

    std::vector<SimulatedGrantRole> simulated_grants;

    std::vector<SimulateBindPermission> simulated_bindings;

    std::vector<SimulatedOwnerOverride> simulated_owner_overrides;
};

// ======================================================
// SimulationResult
// 作用：表示模拟判断的结果
// ======================================================
struct SimulationResult {

    bool allowed = false;

    std::string reason;

    std::string deny_code;

    std::vector<std::string> current_roles;

    std::vector<std::string> suggest_roles;

    std::vector<std::string> matched_roles;

    std::vector<std::string> matched_permissions;

    bool owner_shortcut_used = false;

    int policy_version = 1;

    std::string decision_source_text = "LIVE_DB_WITH_SIMULATION";

    std::vector<std::string> applied_simulations;

    std::string trace_text;
};

// ======================================================
// SimulationEngine
// 作用：
// 1. 读取当前真实策略数据
// 2. 在内存中叠加模拟改动
// 3. 给出“如果这么改，会发生什么”的判断结果
//
// 特别说明：
// - 它不会写正式数据库
// - 它不会污染运行时缓存
// - 它只服务于 V2 管理端的 SimulateCheck
// ======================================================
class SimulationEngine {
public:

    using RoleSet = std::unordered_set<std::string>;
    
    using PermissionSet = std::unordered_set<std::string>;

    SimulationEngine(std::shared_ptr<PermissionDAO> permission_dao, std::shared_ptr<AdminDAO> admin_dao);

    SimulationResult Simulate(const SimulationRequest& request);

private:

    bool validateRequest(const SimulationRequest& request, SimulationResult& result);

    RoleSet buildEffectiveRoles(const SimulationRequest& request, SimulationResult& result);

    PermissionSet buildEffectivePermssions(const SimulationRequest& request, const RoleSet& effective_roles, SimulationResult& result);

    std::optional<std::string> resolveEffectiveOwner(const SimulationRequest& request, SimulationResult& result);

    bool tryOwnerShortcut(const SimulationRequest& request, SimulationResult& result);

    void evaluateByRbac(const SimulationRequest& request, const RoleSet& effective_roles, const PermissionSet& effective_permissions, SimulationResult& result);

    bool hasSimulatedBinding(const SimulationRequest& request, const std::string& role_key, const std::string& perm_key) const;

    bool hasSimulatedGrant(const SimulationRequest& request, const std::string& user_id, const std::string& role_key) const;

    std::optional<std::string> findSimulatedOwnerOverride(const SimulationRequest& request) const;

    std::vector<std::string> roleSetToVector(const RoleSet& roles) const;

    std::vector<std::string> permissionSetToVector(const PermissionSet& perms) const;

    std::string joinStrings(const std::vector<std::string>& items) const;

private:

    std::shared_ptr<PermissionDAO> permission_dao_;

    std::shared_ptr<AdminDAO> admin_dao_;

};

#endif