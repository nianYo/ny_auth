-- =========================================================
-- ny_auth 数据库初始化脚本（新版）
-- 目标：
-- 1. 支持基础 RBAC：用户 -> 角色 -> 权限
-- 2. 支持资源 owner 快捷规则
-- 3. 支持策略版本号
-- 4. 支持记录每次权限决策的日志
-- =========================================================

-- 如果数据库不存在，就创建数据库 ny_auth
CREATE DATABASE IF NOT EXISTS ny_auth DEFAULT CHARSET utf8mb4;

-- 切换到 ny_auth 数据库
USE ny_auth;

-- =========================================================
-- 为了方便反复调试，这里先按“从依赖最弱到最强”的顺序删表
-- 注意：这会删除旧数据
-- =========================================================
DROP TABLE IF EXISTS ny_decision_logs;
DROP TABLE IF EXISTS ny_resources;
DROP TABLE IF EXISTS ny_user_roles;
DROP TABLE IF EXISTS ny_role_permissions;
DROP TABLE IF EXISTS ny_permissions;
DROP TABLE IF EXISTS ny_roles;
DROP TABLE IF EXISTS ny_policy_versions;
DROP TABLE IF EXISTS ny_apps;

-- =========================================================
-- 1) 应用表 ny_apps
-- 作用：
-- 记录有哪些业务系统接入了 ny_auth
-- 例如：doc_center、course_hub、group_bot
-- =========================================================
CREATE TABLE ny_apps (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    app_name VARCHAR(64) NOT NULL,

    app_code VARCHAR(64) NOT NULL UNIQUE,

    app_secret VARCHAR(128) NOT NULL,

    description VARCHAR(255) DEFAULT '',

    --状态：1表示启用，0表示禁用
    status TINYINT NOT NULL DEFAULT 1,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- =========================================================
-- 2) 策略版本表 ny_policy_versions
-- 作用：
-- 记录每个应用当前生效的策略版本
-- 后续缓存 key 会带上这个版本号，避免粗暴清缓存
-- =========================================================
CREATE TABLE ny_policy_versions (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    app_id BIGINT NOT NULL,

    --当前生效的版本号
    current_version INT NOT NULL DEFAULT 1,

    published_by VARCHAR(64) DEFAULT '',

    publish_note VARCHAR(255) DEFAULT '',

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_app_policy_version(app_id)
);

-- =========================================================
-- 3) 角色表 ny_roles
-- 作用：
-- 记录某个应用下有哪些角色
-- 例如：admin、editor、viewer
-- =========================================================
CREATE TABLE ny_roles (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    app_id BIGINT NOT NULL,

    role_name VARCHAR(64) NOT NULL,

    role_key VARCHAR(64) NOT NULL,

    description VARCHAR(255) DEFAULT '',

    is_default TINYINT NOT NULL DEFAULT 0,

    status TINYINT NOT NULL DEFAULT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_app_role(app_id,role_key),

    KEY idx_role_app_id(app_id)
);

-- =========================================================
-- 4) 权限表 ny_permissions
-- 作用：
-- 记录某个应用下有哪些权限
-- 1. resource_type：这个权限作用于哪类资源
-- 2. owner_shortcut_enabled：是否允许资源 owner 快捷通过
-- =========================================================
CREATE TABLE ny_permissions (

    id BIGINT PRIMAYR KEY AUTO_INCREMENT,

    app_id BIGINT NOT NULL,

    perm_name VARCHAR(64) NOT NULL,

    perm_key VARCHAR(64) NOT NULL,

    resource_type VARCHAR(64) DEFAULT '',

    owner_shortcut_enabled TINYINT NOT NULL DEFAULT 0,

    description VARCHAR(255) DEFAULT '',

    status TINYINT NOT NULL DEFAULT 1,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_app_perm(app_id,perm_key),

    KEY idx_perm_app_source(app_id,resource_type)
);

-- =========================================================
-- 5) 角色-权限关联表 ny_role_permissions
-- 作用：
-- 记录某个角色拥有哪些权限
-- 例如：editor -> document:edit
-- =========================================================
CREATE TABLE ny_role_permissions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    role_id BIGINT NOT NULL,

    perm_id BIGINT NOT NULL,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uk_role_perm(role_id,perm_id),

    KEY idx_role_perm_perm_id(perm_id)
);

-- =========================================================
-- 6) 用户-角色关联表 ny_user_roles
-- 作用：
-- 记录某个用户被授予了哪些角色
-- 例如：u1001 -> editor
-- =========================================================
CREATE TABLE ny_user_roles (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    app_id BIGINT NOT NULL,

    app_user_id VARCHAR(128) NOT NULL,

    role_id BIGINT NOT NULL,

    granted_by VARCHAR(64) DEFAULT '',

    cretated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_app_user_role(app_id,app_user_id,role_id),

    KEY idx_user_role_lookup(app_id,app_user_id),

    KEY idx_user_role_role_id(role_id)
);

-- =========================================================
-- 7) 资源表 ny_resources
-- 作用：
-- 记录系统中的资源，以及这个资源归谁所有
-- 这是 owner 快捷规则的数据基础
-- 例如：doc_001 这篇文档属于 u1001
-- =========================================================
CREATE TABLE ny_resources (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    app_id BIGINT NOT NULL,

    resource_type VARCHAR(64) NOT NULL,

    resource_id VARCHAR(128) NOT NULL,

    resource_name VARCHAR(128) DEFAULT '',

    owner_user_id VARCHAR(128) NOT NULL,

    metadata_text TEXT,

    status TINYINT NOT NULL DEFAULT 1,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_app_resource(app_id,resource_type,resource_id),

    KEY idx_resource_lookup (app_id,resource_type,resource_id),

    KEY idx_resource_owner_lookup(app_id,owner_user_id)
);

-- =========================================================
-- 8) 决策日志表 ny_decision_logs
-- 作用：
-- 记录每一次权限判断的结果和解释
-- 这不是“管理员改配置”的审计日志，而是“每次鉴权本身”的日志
-- =========================================================
CREATE TABLE ny_decision_logs (

    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    app_id BIGINT NOT NULL,

    app_code VARCHAR(64) NOT NULL,

    user_id VARCHAR(128) NOT NULL,

    perm_key VARCHAR(64) NOT NULL,

    resource_type VARCHAR(64) DEFAULT '',

    resource_id VARCHAR(128) DEFAULT '',

    allowed TINYINT NOT NULL DEFAULT 0,

    descision_source VARCHAR(32) NOT NULL DEFAULT 'DB',

    matched_roles VARCHAR(255) DEFAULT '',

    matched_permissions VARCHAR(255) DEFAULT '',

    owner_shortcut_used TINYINT NOT NULL DEFAULT 0,

    policy_version INT NOT NULL DEFAULT 1,

    deny_code VARCHAR(64) DEFAULT '',

    reason VARCHAR(255) DEFAULT '',

    trance_text TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    KEY idx_decision_app_time(app_id,created_at),
    KEY idx_decision_user_time(user_id,created_at),
    KEY idx_decision_perm_time(perm_id,created_at)
);

-- =========================================================
-- 下面开始插入测试数据
-- 这部分很重要，因为没有测试数据，你后面没法调 Check 接口
-- =========================================================

-- ---------------------------------------------------------
-- 插入一个测试应用：文档协作平台
-- 这是我们的主测试 app
-- ---------------------------------------------------------
INSERT INTO ny_apps(app_name,app_code,app_secret,description,status)
VALUES('文档协作平台','doc_center','secret_doc_center_123','带owner规则和决策解释的文档平台',1);

SET @app_id = (SELECT id FROM ny_apps WHERE app_code = 'doc_center');

-- ---------------------------------------------------------
-- 初始化策略版本
-- 一开始先从第 1 版开始
-- ---------------------------------------------------------
INSERT INTO ny_policy_versions(app_id,current_version,published_by,publish_note)
VALUES(@app_id, 1, 'system','初始化策略版本');

-- ---------------------------------------------------------
-- 插入角色
-- admin  ：管理员
-- editor ：编辑者
-- viewer ：只读用户
-- ---------------------------------------------------------
INSERT INTO ny_roles(app_id,role_name,role_key,description,is_default,status)
VALUES
(@app_id, '管理员', 'admin', '拥有系统高权限', 0, 1),
(@app_id, '编辑者', 'editor', '可读写文档', 0, 1),
(@app_id, '浏览者', 'viewer', '只能查看文档', 1, 1);

