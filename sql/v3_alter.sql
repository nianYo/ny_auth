-- =========================================================
-- ny_auth V3 数据库升级脚本
-- 目标：
-- 1. 新增策略快照表 ny_policy_snapshots
-- 2. 新增快照发布日志表 ny_snapshot_publish_logs
-- 3. 为后续本地 Agent / Sidecar 拉取策略快照做准备
-- =========================================================

USE ny_auth;

-- =========================================================
-- 1) 策略快照表 ny_policy_snapshots
--
-- 作用：
-- 每次发布策略后，把“当时的完整只读策略视图”固化成一份快照。
--
-- 一份快照至少包含：
-- - app_code
-- - policy_version
-- - snapshot_json
-- - 发布人
-- - 发布说明
--
-- 后面本地 Agent 拉取的就是这里的数据。
-- =========================================================
CREATE TABLE IF NOT EXISTS ny_policy_snapshots (
    -- 主键，自增
    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    -- 所属应用 id
    app_id BIGINT NOT NULL,

    -- 所属应用编码，冗余保存，查询和调试更方便
    app_code VARCHAR(64) NOT NULL,

    -- 对应的策略版本号
    policy_version INT NOT NULL,

    -- 快照内容，JSON 字符串
    -- V3 第一版先直接存 TEXT，后面可以升级成 JSON 类型
    snapshot_json LONGTEXT NOT NULL,

    -- 快照状态：
    -- 1 = 已发布
    -- 0 = 已失效 / 已废弃
    status TINYINT NOT NULL DEFAULT 1,

    -- 发布人
    published_by VARCHAR(64) DEFAULT '',

    -- 发布说明
    publish_note VARCHAR(255) DEFAULT '',

    -- 创建时间
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- 更新时间
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- 约束：同一个 app 的同一个 policy_version 只能有一份快照
    UNIQUE KEY uk_snapshot_app_version(app_id, policy_version),

    -- 常用查询索引
    KEY idx_snapshot_app_code_version(app_code, policy_version),
    KEY idx_snapshot_app_status(app_id, status)
);

-- =========================================================
-- 2) 快照发布日志表 ny_snapshot_publish_logs
--
-- 作用：
-- 记录“哪次快照是怎么生成和发布的”
--
-- 注意：
-- 这和 ny_audit_logs 不一样：
-- - ny_audit_logs            记录管理员做了什么配置操作
-- - ny_snapshot_publish_logs 记录快照构建/发布过程本身
-- =========================================================
CREATE TABLE IF NOT EXISTS ny_snapshot_publish_logs (
    -- 主键，自增
    id BIGINT PRIMARY KEY AUTO_INCREMENT,

    -- 应用 id
    app_id BIGINT NOT NULL,

    -- 应用编码
    app_code VARCHAR(64) NOT NULL,

    -- 对应策略版本
    policy_version INT NOT NULL,

    -- 对应快照 id
    snapshot_id BIGINT NOT NULL,

    -- 发布人
    published_by VARCHAR(64) DEFAULT '',

    -- 发布结果：
    -- SUCCESS / FAILED
    publish_result VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',

    -- 详细说明
    trace_text TEXT,

    -- 创建时间
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- 常用索引
    KEY idx_snapshot_publish_app_version(app_code, policy_version),
    KEY idx_snapshot_publish_result_time(publish_result, created_at)
);

-- 注意：
-- 不在 SQL 初始化阶段写入样例快照。
-- 快照 JSON 必须由 SnapshotBuilder 从真实策略表生成，否则 Agent 激活后会拿到
-- 缺少 roles / permissions / bindings / owners 的空壳快照。
