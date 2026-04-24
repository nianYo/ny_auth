-- =========================================================
-- ny_auth V2 数据库升级脚本
-- 目标：
-- 1. 新增管理端管理员账号表 ny_console_users
-- 2. 新增审计日志表 ny_audit_logs
-- 3. 插入一个默认管理员账号，便于后续测试 Login
-- =========================================================

-- 切换到 ny_auth 数据库
USE ny_auth;

-- =========================================================
-- 1) 管理员账号表 ny_console_users
-- 作用：
-- 管理端登录使用，不是业务系统普通用户
-- 例如：
--   admin
--   ops
--   security_admin
-- =========================================================
CREATE TABLE IF NOT EXISTS ny_console_users (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    username VARCHAR(64) NOT NULL UNIQUE,

    password_hash VARCHAR(255) NOT NULL,

    display_name VARCHAR(64) DEFAULT '',
    
    status TINYINT NOT NULL DEFAULT 1,

    is_super_admin TINYINT NOT NULL DEFAULT 1,

    last_login_at DATETIME NULL,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- =========================================================
-- 2) 审计日志表 ny_audit_logs
-- 作用：
-- 记录管理员对权限策略做了什么修改
-- 注意：
-- 这和 ny_decision_logs 不一样
-- - ny_decision_logs 记录“每次鉴权”
-- - ny_audit_logs   记录“每次配置变更”
-- =========================================================
CREATE TABLE IF NOT EXISTS ny_audit_logs (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    operator_user_id BIGINT NOT NULL,

    operator_username VARCHAR(64) NOT NULL,

    operator_display_name VARCHAR(64) DEFAULT '',

    app_code VARCHAR(64) NOT NULL,

    action_type VARCHAR(64) NOT NULL,

    target_type VARCHAR(64) NOT NULL,

    target_key VARCHAR(128) NOT NULL,

    before_text TEXT,

    after_text TEXT,

    trace_text TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    KEY idx_audit_app_time (app_code, created_at),
    KEY idx_audit_operator_time (operator_username, created_at),
    KEY idx_audit_action_time (action_type, created_at)
);

-- =========================================================
-- 3) 插入默认管理员账号
-- 说明：
-- 为了方便你后面立刻测试 V2 登录接口，
-- 这里先插入一个默认管理员 admin
--
-- 默认账号：
--   username = admin
--   password = admin123
-- =========================================================
INSERT INTO ny_console_users (

    username,

    password_hash,

    display_name,

    status,

    is_super_admin
)
VALUES (
    'admin',
    'admin123',
    '系统管理员',
    1,
    1
)
ON DUPLICATE KEY UPDATE

    display_name = VALUES(display_name),
    status = VALUES(status),
    is_super_admin = VALUES(is_super_admin);

-- =========================================================
-- 4) 插入一条样例审计日志
-- =========================================================
INSERT INTO ny_audit_logs (

    operator_user_id,

    operator_username,

    operator_display_name,

    app_code,

    action_type,

    target_type,

    target_key,

    before_text,

    after_text,

    trace_text
)
VALUES (
    1,
    'admin',
    '系统管理员',
    'doc_center',
    'INIT_V2_AUDIT',
    'system',
    'v2_bootstrap',
    '',
    'created ny_console_users and ny_audit_logs',
    'seed audit log for v2 bootstrap'
);
