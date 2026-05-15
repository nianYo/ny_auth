#ifndef NY_AUTH_SNAPSHOT_DAO_H
#define NY_AUTH_SNAPSHOT_DAO_H

// 提供 int64_t
#include <cstdint>

// 提供 std::mutex
#include <mutex>

// 提供 std::optional
#include <optional>

// 提供 std::string
#include <string>

// 提供 std::vector
#include <vector>

// MySQL Connector/C++ 头文件
#include <cppconn/connection.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <mysql_driver.h>

// 引入快照数据结构
#include "snapshot_types.h"

// ======================================================
// SnapshotPublishLogRecord
// 作用：表示一条“待写入数据库”的快照发布日志
// 对应表：ny_snapshot_publish_logs
// ======================================================
struct SnapshotPublishLogRecord {
    // 应用 id
    int64_t app_id = 0;

    // 应用编码
    std::string app_code;

    // 对应策略版本号
    int policy_version = 1;

    // 对应快照 id
    int64_t snapshot_id = 0;

    // 发布人
    std::string published_by;

    // 发布结果
    // 例如 SUCCESS / FAILED
    std::string publish_result;

    // 更完整的说明
    std::string trace_text;
};

// ======================================================
// SnapshotPublishLogItem
// 作用：表示“从数据库查出来”的快照发布日志结果
// 比 SnapshotPublishLogRecord 多了 id 和 created_at
// ======================================================
struct SnapshotPublishLogItem {
    // 日志 id
    int64_t id = 0;

    // 应用 id
    int64_t app_id = 0;

    // 应用编码
    std::string app_code;

    // 对应策略版本号
    int policy_version = 1;

    // 对应快照 id
    int64_t snapshot_id = 0;

    // 发布人
    std::string published_by;

    // 发布结果
    std::string publish_result;

    // 更完整说明
    std::string trace_text;

    // 创建时间（字符串）
    std::string created_at;
};

// ======================================================
// SnapshotDAO
// 作用：V3 快照体系的数据访问层
//
// 它负责：
// 1. 快照写入
// 2. 快照查询
// 3. 快照发布日志写入
// 4. 快照发布日志查询
//
// 注意：
// - 它不负责构建快照内容
// - 它不负责本地判权
// - 它只负责和数据库交互
// ======================================================
class SnapshotDAO {
public:
    // 构造函数：保存数据库连接参数
    SnapshotDAO(const std::string& host,
                int port,
                const std::string& user,
                const std::string& password,
                const std::string& database);

    // --------------------------------------------------
    // 快照本体相关
    // --------------------------------------------------

    // 保存一份快照
    // 说明：
    // - 如果同一个 app_id + policy_version 已存在，会执行覆盖更新
    // - 返回值：
    //     成功 -> 快照主键 id
    //     失败 -> 0
    int64_t saveSnapshot(const PolicySnapshot& snapshot,
                         const std::string& snapshot_json);

    // 按 app_code + policy_version 查询某一版快照
    // 查到 -> 返回 PolicySnapshot
    // 查不到 -> 返回 std::nullopt
    std::optional<PolicySnapshot> getSnapshotByVersion(const std::string& app_code,
                                                       int policy_version);

    // 查询某个 app 当前最新已发布快照
    // 规则：
    // - status = 1
    // - 按 policy_version 倒序取 1 条
    std::optional<PolicySnapshot> getLatestSnapshot(const std::string& app_code);

    // 查询某个 app 是否已经存在某个版本的快照
    bool snapshotExists(const std::string& app_code,
                        int policy_version);

    // 查询某个 app 的快照列表（按版本倒序）
    // limit <= 0 时，默认 20
    std::vector<SnapshotMeta> listSnapshotMetas(const std::string& app_code,
                                                int limit);

    // --------------------------------------------------
    // 快照发布日志相关
    // --------------------------------------------------

    // 写入一条快照发布日志
    bool insertSnapshotPublishLog(const SnapshotPublishLogRecord& record);

    // 查询快照发布日志
    // 过滤规则：
    // - app_code 为空 -> 不按 app 过滤
    // - publish_result 为空 -> 不按结果过滤
    // - limit <= 0 -> 默认 20
    std::vector<SnapshotPublishLogItem> listSnapshotPublishLogs(
        const std::string& app_code,
        const std::string& publish_result,
        int limit);

    // --------------------------------------------------
    // 通用能力
    // --------------------------------------------------

    // 检查数据库是否可连通
    bool isConnected() const;

    // 获取最近一次数据库错误
    std::string getLastError() const;

private:
    // 创建数据库连接
    sql::Connection* createConnection();

    // 线程安全地记录最近一次错误
    void setLastError(const std::string& error);

    // 把 PolicySnapshot 序列化成 JSON 字符串
    // 当前 V3 第一版先手工拼简单 JSON，后面可以换真正 JSON 库
    std::string serializeSnapshotToJson(const PolicySnapshot& snapshot) const;

    // 把数据库中的一条快照记录反序列化成 PolicySnapshot
    // 当前 V3 第一版先保留接口，cpp 里会实现一个“最低可用版本”
    // 说明：
    // - 真正严谨的 JSON 解析，后面可以升级
    std::optional<PolicySnapshot> deserializeSnapshotFromJson(
        int64_t snapshot_id,
        const std::string& app_code,
        int policy_version,
        const std::string& snapshot_json,
        const std::string& published_by,
        const std::string& publish_note,
        const std::string& created_at) const;

private:
    // MySQL 主机
    std::string host_;

    // MySQL 端口
    int port_;

    // 用户名
    std::string user_;

    // 密码
    std::string password_;

    // 数据库名
    std::string database_;

    // 保护 last_error_
    mutable std::mutex error_mutex_;

    // 最近一次错误
    std::string last_error_;
};

#endif