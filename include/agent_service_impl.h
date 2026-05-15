#ifndef NY_AUTH_AGENT_SERVICE_IMPL_H
#define NY_AUTH_AGENT_SERVICE_IMPL_H

// 提供 std::shared_ptr
#include <memory>

// 提供 std::string
#include <string>

// protobuf / brpc service 相关头文件
#include <google/protobuf/stubs/callback.h>
#include <google/protobuf/service.h>

// 引入 agent proto 自动生成头文件
#include "agent.pb.h"

// 引入快照 DAO
#include "snapshot_dao.h"

// 引入快照构建器
#include "snapshot_builder.h"

// 引入本地快照判权引擎
#include "local_snapshot_engine.h"

// ======================================================
// AgentServiceImpl
// 作用：
// 1. 继承 proto 中定义的 ny::agent::AgentService
// 2. 提供快照拉取接口
// 3. 提供快照激活接口
// 4. 提供本地快照状态查询接口
// 5. 提供本地快照判权接口
//
// 注意：
// - 它是 RPC 接入层，不负责直接写复杂业务逻辑
// - 它会协调 SnapshotDAO / SnapshotBuilder / LocalSnapshotEngine
// ======================================================
class AgentServiceImpl : public ny::agent::AgentService {
public:
    // 构造函数
    AgentServiceImpl(std::shared_ptr<SnapshotDAO> snapshot_dao,
                     std::shared_ptr<SnapshotBuilder> snapshot_builder,
                     std::shared_ptr<LocalSnapshotEngine> local_snapshot_engine);

    // ==================================================
    // Agent 侧 RPC 接口实现
    // ==================================================

    // 拉取最新快照
    void PullLatestSnapshot(google::protobuf::RpcController* cntl,
                            const ny::agent::PullLatestSnapshotRequest* request,
                            ny::agent::PullLatestSnapshotResponse* response,
                            google::protobuf::Closure* done) override;

    // 拉取指定版本快照
    void PullSnapshotByVersion(google::protobuf::RpcController* cntl,
                               const ny::agent::PullSnapshotByVersionRequest* request,
                               ny::agent::PullSnapshotByVersionResponse* response,
                               google::protobuf::Closure* done) override;

    // 激活最新快照
    void ActivateLatestSnapshot(google::protobuf::RpcController* cntl,
                                const ny::agent::ActivateLatestSnapshotRequest* request,
                                ny::agent::ActivateLatestSnapshotResponse* response,
                                google::protobuf::Closure* done) override;

    // 激活指定版本快照
    void ActivateSnapshotByVersion(google::protobuf::RpcController* cntl,
                                   const ny::agent::ActivateSnapshotByVersionRequest* request,
                                   ny::agent::ActivateSnapshotByVersionResponse* response,
                                   google::protobuf::Closure* done) override;

    // 查询当前本地快照状态
    void GetLocalSnapshotStatus(google::protobuf::RpcController* cntl,
                                const ny::agent::GetLocalSnapshotStatusRequest* request,
                                ny::agent::GetLocalSnapshotStatusResponse* response,
                                google::protobuf::Closure* done) override;

    // 基于当前本地快照做本地判权
    void LocalCheck(google::protobuf::RpcController* cntl,
                    const ny::agent::LocalCheckRequest* request,
                    ny::agent::LocalCheckResponse* response,
                    google::protobuf::Closure* done) override;

private:
    // ==================================================
    // proto -> internal request 转换
    // ==================================================

    // 构造本地快照判权内部请求
    LocalSnapshotCheckRequest buildLocalCheckRequest(
        const ny::agent::LocalCheckRequest& request) const;

    // ==================================================
    // proto response 填充辅助
    // ==================================================

    // 统一填充 AgentOperationStatus
    void fillAgentOperationStatus(bool success,
                                  const std::string& message,
                                  const std::string& error_code,
                                  ny::agent::AgentOperationStatus* status) const;

    // 把 PolicySnapshot + snapshot_json 填进 SnapshotPayload
    void fillSnapshotPayload(const PolicySnapshot& snapshot,
                             const std::string& snapshot_json,
                             ny::agent::SnapshotPayload* payload) const;

    // 填充本地快照状态
    void fillLocalSnapshotStatus(ny::agent::LocalSnapshotStatus* status) const;

    // 填充本地判权响应
    void fillLocalCheckResponse(const LocalSnapshotCheckResult& result,
                                ny::agent::LocalCheckResponse* response) const;

    // ==================================================
    // 映射辅助
    // ==================================================

    // 内部字符串错误码 -> proto AgentErrorCode
    ny::agent::AgentErrorCode mapAgentErrorCodeToProto(
        const std::string& error_code) const;

    // 本地判权 deny_code -> auth.proto DenyCode
    ny::auth::DenyCode mapLocalDenyCodeToProto(
        const std::string& deny_code) const;

    // 本地判权来源 -> auth.proto DecisionSource
    ny::auth::DecisionSource mapLocalDecisionSourceToProto(
        const std::string& decision_source_text) const;

    // ==================================================
    // 快照处理辅助
    // ==================================================

    // 把 PolicySnapshot 转成 JSON 文本
    // 说明：
    // - 当前 V3 第一版里，SnapshotDAO 查询接口返回的是结构化快照
    // - 但 agent.proto 的 SnapshotPayload 需要 snapshot_json
    // - 所以这里补一个 service 层可用的序列化函数
    std::string serializeSnapshotToJson(const PolicySnapshot& snapshot) const;

private:
    // 快照 DAO
    std::shared_ptr<SnapshotDAO> snapshot_dao_;

    // 快照构建器
    std::shared_ptr<SnapshotBuilder> snapshot_builder_;

    // 本地快照判权引擎
    std::shared_ptr<LocalSnapshotEngine> local_snapshot_engine_;
};

#endif