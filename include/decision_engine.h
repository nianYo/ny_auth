#ifndef NY_AUTH_DECISION_ENGINE_H
#define NU_AUTH_DECISION_ENGINE_H

#include <memory>

#include <string>

#include <unordered_set>

#include "local_cache.h"

#include "permission_dao.h"

// ======================================================
// DecisionSourceType：内部决策来源类型
// 注意：这是引擎内部使用的类型
// 后面 AuthServiceImpl 再把它转换成 proto 里的 DecisionSource
// ======================================================
enum class DecisionSourceType {

    kUnknown = 0,

    KCache = 1,

    kDatabase = 2
};

// ======================================================
// DecisionRequest：决策引擎内部请求对象
// 这是把 RPC 请求“翻译”成业务层通用结构
// 好处：DecisionEngine 不直接依赖 proto
// ======================================================
struct DecisionRequest {

    std::string app_code;

    std::string user_id;

    std::string perm_key;

    std::string resource_type;

    std::string resource_id;

    std::string request_id;
};

// ======================================================
// DecisionResult：决策引擎内部返回结果
// 后面 AuthServiceImpl 会把它转换成 proto CheckResponse
// ======================================================
struct DecisionResult {

    bool allowed = false;

    std::string reason;

    std::string deny_code;

    std::vector<std::string> current_roles;

    std::vector<std::string> suggest_roles;

    std::vector<std::string> matched_roles;

    std::vector<std::string> matched_permissions;

    bool owner_shortcut_used = false;

    DecisionSourceType decision_source = DecisionSourceType::kUnknown;

    int policy_version = 1;

    std::string trace_text;
};

// ======================================================
// DecisionEngine：权限决策引擎
// 负责：
// 1. 校验请求参数
// 2. 查询 app 信息与策略版本
// 3. 查缓存
// 4. 判断 owner 快捷规则
// 5. 判断 RBAC 权限
// 6. 组装解释结果
// ======================================================
class DecisionEngine {
public:

    using UserPermSet = std::unordered_set<std::string>;

    DecisionEngine(std::shared_ptr<LocalCache<UserPermSet>> cache, std::shared_ptr<PermissionDAO> dao, int cache_ttl);

    DecisionResult Evaluate(const DecisionRequest& request);

private:

    bool validateRequest(const DecisionRequest& request, DecisionResult& result);

    UserPermSet loadUserPermissions(const std::string& app_code, const std::string& user_id, int policy_version, DecisionResult& result);

    bool tyrOwnerShortcut(const DecisionRequest& request, DecisionResult& result);

    void evaluateByRbac(const DecisionRequest& request, const UserPermSet& user_permissions, DecisionResult& result);

    std::string joinStrings(const std::vector<std::string>& items) const;

    std::string decisionSourceToString(DecisionSourceType source) const;

private:

    std::shared_ptr<LocalCache<UserPermSet>> cache_;

    std::shared_ptr<PermissionDAO> dao_;

    int cache_ttl_;
};

#endif