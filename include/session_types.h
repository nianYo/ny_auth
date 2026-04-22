#ifndef NY_AUTH_SESSION_TYPES_H
#define NY_AUTH_SESSION_TYPES_H

#include <cstdint>

#include <string>

// ======================================================
// BuildAdminSessionCacheKey
// 作用：生成管理员会话缓存 key
// ======================================================
inline std::string BuildAdminSessionCacheKey(const std::string& token) {

    return "admin_session : " + token;
}

// ======================================================
// AdminSessionInfo
// 作用：表示“一个已经登录成功的管理员会话”
//
// 这个结构会被放进 LocalCache<AdminSessionInfo> 里，
// 后面拿着 operator_token 来查缓存时，读出来的就是它。
// ======================================================
struct AdminSessionInfo {

    int64_t user_id = 0;

    std::string username;

    std::string display_name;

    bool is_super_admin = false;

    std::string token;

    int64_t login_at_unix_seconds = 0;
};


// ======================================================
// OperatorIdentity
// 作用：表示“当前这次管理请求的操作者身份”
//
// 和 AdminSessionInfo 的区别：
// - AdminSessionInfo 更像“缓存里保存的登录会话”
// - OperatorIdentity 更像“已经通过 token 校验后，可直接用于业务逻辑的操作者信息”
// ======================================================
struct OperatorIdentity {

    bool authenticated = false;

    int64_t user_id = 0;

    std::string username;

    std::string display_name;

    bool is_super_admin = false;

    std::string token;
};

#endif