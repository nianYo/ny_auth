#include "agent_service_impl.h"

// brpc 用于自动结束 RPC
#include <brpc/closure_guard.h>
#include <brpc/controller.h>

// 提供 std::move
#include <utility>

// 提供字符串拼接
#include <sstream>

namespace {

// ======================================================
// 辅助函数：JSON 字符串转义
// 作用：让字符串能安全写入 JSON 文本
// ======================================================
std::string EscapeJsonString(const std::string& input) {
    std::ostringstream oss;

    for (char ch : input) {
        switch (ch) {
            case '\"':
                oss << "\\\"";
                break;
            case '\\':
                oss << "\\\\";
                break;
            case '\b':
                oss << "\\b";
                break;
            case '\f':
                oss << "\\f";
                break;
            case '\n':
                oss << "\\n";
                break;
            case '\r':
                oss << "\\r";
                break;
            case '\t':
                oss << "\\t";
                break;
            default:
                oss << ch;
                break;
        }
    }

    return oss.str();
}

// ======================================================
// 填充“请求对象为空”错误
// ======================================================
void FillNullRequestStatus(ny::agent::AgentOperationStatus* status) {
    if (status == nullptr) {
        return;
    }

    status->set_success(false);
    status->set_message("请求对象为空");
    status->set_error_code(ny::agent::AGENT_ERROR_CODE_INVALID_ARGUMENT);
}

// ======================================================
// 填充“依赖未初始化”错误
// ======================================================
void FillDependencyNotReadyStatus(ny::agent::AgentOperationStatus* status,
                                  const std::string& dependency_name) {
    if (status == nullptr) {
        return;
    }

    status->set_success(false);
    status->set_message("系统内部错误：" + dependency_name + " 未初始化");
    status->set_error_code(ny::agent::AGENT_ERROR_CODE_INTERNAL_ERROR);
}

}  // namespace

// ======================================================
// 构造函数
// ======================================================
AgentServiceImpl::AgentServiceImpl(
    std::shared_ptr<SnapshotDAO> snapshot_dao,
    std::shared_ptr<SnapshotBuilder> snapshot_builder,
    std::shared_ptr<LocalSnapshotEngine> local_snapshot_engine)
    : snapshot_dao_(std::move(snapshot_dao)),
      snapshot_builder_(std::move(snapshot_builder)),
      local_snapshot_engine_(std::move(local_snapshot_engine)) {}

// ======================================================
// PullLatestSnapshot
// 作用：拉取某个 app 的最新快照，但不激活本地快照
// ======================================================
void AgentServiceImpl::PullLatestSnapshot(
    google::protobuf::RpcController* cntl,
    const ny::agent::PullLatestSnapshotRequest* request,
    ny::agent::PullLatestSnapshotResponse* response,
    google::protobuf::Closure* done) {
    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;

    if (response == nullptr) {
        return;
    }

    if (request == nullptr) {
        FillNullRequestStatus(response->mutable_status());
        return;
    }

    if (!snapshot_dao_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "SnapshotDAO");
        return;
    }

    if (request->app_code().empty()) {
        fillAgentOperationStatus(
            false,
            "参数不完整：app_code 不能为空",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    auto snapshot_opt = snapshot_dao_->getLatestSnapshot(request->app_code());
    if (!snapshot_opt.has_value()) {
        fillAgentOperationStatus(
            false,
            "快照不存在",
            "NOT_FOUND",
            response->mutable_status());
        return;
    }

    const PolicySnapshot snapshot = snapshot_opt.value();
    const std::string snapshot_json = serializeSnapshotToJson(snapshot);

    fillAgentOperationStatus(
        true,
        "拉取最新快照成功",
        "OK",
        response->mutable_status());

    fillSnapshotPayload(snapshot, snapshot_json, response->mutable_snapshot());
}

// ======================================================
// PullSnapshotByVersion
// 作用：按 app_code + policy_version 拉取指定快照
// ======================================================
void AgentServiceImpl::PullSnapshotByVersion(
    google::protobuf::RpcController* cntl,
    const ny::agent::PullSnapshotByVersionRequest* request,
    ny::agent::PullSnapshotByVersionResponse* response,
    google::protobuf::Closure* done) {
    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;

    if (response == nullptr) {
        return;
    }

    if (request == nullptr) {
        FillNullRequestStatus(response->mutable_status());
        return;
    }

    if (!snapshot_dao_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "SnapshotDAO");
        return;
    }

    if (request->app_code().empty()) {
        fillAgentOperationStatus(
            false,
            "参数不完整：app_code 不能为空",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    if (request->policy_version() <= 0) {
        fillAgentOperationStatus(
            false,
            "参数不合法：policy_version 必须大于 0",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    auto snapshot_opt = snapshot_dao_->getSnapshotByVersion(
        request->app_code(),
        request->policy_version()
    );
    if (!snapshot_opt.has_value()) {
        fillAgentOperationStatus(
            false,
            "指定版本快照不存在",
            "NOT_FOUND",
            response->mutable_status());
        return;
    }

    const PolicySnapshot snapshot = snapshot_opt.value();
    const std::string snapshot_json = serializeSnapshotToJson(snapshot);

    fillAgentOperationStatus(
        true,
        "拉取指定版本快照成功",
        "OK",
        response->mutable_status());

    fillSnapshotPayload(snapshot, snapshot_json, response->mutable_snapshot());
}

// ======================================================
// ActivateLatestSnapshot
// 作用：
// 1. 拉取某个 app 最新快照
// 2. 建立索引
// 3. 加载到 LocalSnapshotEngine
// ======================================================
void AgentServiceImpl::ActivateLatestSnapshot(
    google::protobuf::RpcController* cntl,
    const ny::agent::ActivateLatestSnapshotRequest* request,
    ny::agent::ActivateLatestSnapshotResponse* response,
    google::protobuf::Closure* done) {
    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;

    if (response == nullptr) {
        return;
    }

    if (request == nullptr) {
        FillNullRequestStatus(response->mutable_status());
        return;
    }

    if (!snapshot_dao_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "SnapshotDAO");
        return;
    }

    if (!snapshot_builder_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "SnapshotBuilder");
        return;
    }

    if (!local_snapshot_engine_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "LocalSnapshotEngine");
        return;
    }

    if (request->app_code().empty()) {
        fillAgentOperationStatus(
            false,
            "参数不完整：app_code 不能为空",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    auto snapshot_opt = snapshot_dao_->getLatestSnapshot(request->app_code());
    if (!snapshot_opt.has_value()) {
        fillAgentOperationStatus(
            false,
            "快照不存在",
            "NOT_FOUND",
            response->mutable_status());
        return;
    }

    const PolicySnapshot snapshot = snapshot_opt.value();

    // 用 SnapshotBuilder 把原始快照转成索引快照
    const IndexedPolicySnapshot indexed_snapshot =
        snapshot_builder_->BuildIndexedSnapshot(snapshot);

    if (!local_snapshot_engine_->LoadSnapshot(indexed_snapshot)) {
        fillAgentOperationStatus(
            false,
            "激活快照失败",
            "INTERNAL_ERROR",
            response->mutable_status());
        return;
    }

    const std::string snapshot_json = serializeSnapshotToJson(snapshot);

    fillAgentOperationStatus(
        true,
        "激活最新快照成功",
        "OK",
        response->mutable_status());

    fillSnapshotPayload(snapshot, snapshot_json, response->mutable_snapshot());
}

// ======================================================
// ActivateSnapshotByVersion
// 作用：
// 1. 拉取指定版本快照
// 2. 建立索引
// 3. 加载到 LocalSnapshotEngine
// ======================================================
void AgentServiceImpl::ActivateSnapshotByVersion(
    google::protobuf::RpcController* cntl,
    const ny::agent::ActivateSnapshotByVersionRequest* request,
    ny::agent::ActivateSnapshotByVersionResponse* response,
    google::protobuf::Closure* done) {
    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;

    if (response == nullptr) {
        return;
    }

    if (request == nullptr) {
        FillNullRequestStatus(response->mutable_status());
        return;
    }

    if (!snapshot_dao_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "SnapshotDAO");
        return;
    }

    if (!snapshot_builder_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "SnapshotBuilder");
        return;
    }

    if (!local_snapshot_engine_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "LocalSnapshotEngine");
        return;
    }

    if (request->app_code().empty()) {
        fillAgentOperationStatus(
            false,
            "参数不完整：app_code 不能为空",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    if (request->policy_version() <= 0) {
        fillAgentOperationStatus(
            false,
            "参数不合法：policy_version 必须大于 0",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    auto snapshot_opt = snapshot_dao_->getSnapshotByVersion(
        request->app_code(),
        request->policy_version()
    );
    if (!snapshot_opt.has_value()) {
        fillAgentOperationStatus(
            false,
            "指定版本快照不存在",
            "NOT_FOUND",
            response->mutable_status());
        return;
    }

    const PolicySnapshot snapshot = snapshot_opt.value();

    const IndexedPolicySnapshot indexed_snapshot =
        snapshot_builder_->BuildIndexedSnapshot(snapshot);

    if (!local_snapshot_engine_->LoadSnapshot(indexed_snapshot)) {
        fillAgentOperationStatus(
            false,
            "激活指定版本快照失败",
            "INTERNAL_ERROR",
            response->mutable_status());
        return;
    }

    const std::string snapshot_json = serializeSnapshotToJson(snapshot);

    fillAgentOperationStatus(
        true,
        "激活指定版本快照成功",
        "OK",
        response->mutable_status());

    fillSnapshotPayload(snapshot, snapshot_json, response->mutable_snapshot());
}

// ======================================================
// GetLocalSnapshotStatus
// 作用：查询当前 LocalSnapshotEngine 的加载状态
// ======================================================
void AgentServiceImpl::GetLocalSnapshotStatus(
    google::protobuf::RpcController* cntl,
    const ny::agent::GetLocalSnapshotStatusRequest* request,
    ny::agent::GetLocalSnapshotStatusResponse* response,
    google::protobuf::Closure* done) {
    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;
    (void)request;

    if (response == nullptr) {
        return;
    }

    if (!local_snapshot_engine_) {
        FillDependencyNotReadyStatus(response->mutable_status(), "LocalSnapshotEngine");
        return;
    }

    fillAgentOperationStatus(
        true,
        "查询本地快照状态成功",
        "OK",
        response->mutable_status());

    fillLocalSnapshotStatus(response->mutable_snapshot_status());
}

// ======================================================
// LocalCheck
// 作用：基于当前已加载的本地快照执行一次本地判权
// ======================================================
void AgentServiceImpl::LocalCheck(
    google::protobuf::RpcController* cntl,
    const ny::agent::LocalCheckRequest* request,
    ny::agent::LocalCheckResponse* response,
    google::protobuf::Closure* done) {
    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;

    if (response == nullptr) {
        return;
    }

    if (request == nullptr) {
        fillAgentOperationStatus(
            false,
            "请求对象为空",
            "INVALID_ARGUMENT",
            response->mutable_status());
        return;
    }

    if (!local_snapshot_engine_) {
        fillAgentOperationStatus(
            false,
            "系统内部错误：LocalSnapshotEngine 未初始化",
            "INTERNAL_ERROR",
            response->mutable_status());
        return;
    }

    const LocalSnapshotCheckRequest internal_request =
        buildLocalCheckRequest(*request);

    const LocalSnapshotCheckResult result =
        local_snapshot_engine_->Check(internal_request);

    fillLocalCheckResponse(result, response);
}

// ======================================================
// buildLocalCheckRequest
// 作用：把 proto 的 LocalCheckRequest 转成内部请求结构
// ======================================================
LocalSnapshotCheckRequest AgentServiceImpl::buildLocalCheckRequest(
    const ny::agent::LocalCheckRequest& request) const {
    LocalSnapshotCheckRequest internal_request;
    internal_request.app_code = request.app_code();
    internal_request.user_id = request.user_id();
    internal_request.perm_key = request.perm_key();
    internal_request.resource_type = request.resource_type();
    internal_request.resource_id = request.resource_id();
    internal_request.request_id = request.request_id();
    return internal_request;
}

// ======================================================
// fillAgentOperationStatus
// 作用：统一填充 AgentOperationStatus
// ======================================================
void AgentServiceImpl::fillAgentOperationStatus(
    bool success,
    const std::string& message,
    const std::string& error_code,
    ny::agent::AgentOperationStatus* status) const {
    if (status == nullptr) {
        return;
    }

    status->set_success(success);
    status->set_message(message);
    status->set_error_code(mapAgentErrorCodeToProto(error_code));
}

// ======================================================
// fillSnapshotPayload
// 作用：把 PolicySnapshot + snapshot_json 填进 SnapshotPayload
// ======================================================
void AgentServiceImpl::fillSnapshotPayload(
    const PolicySnapshot& snapshot,
    const std::string& snapshot_json,
    ny::agent::SnapshotPayload* payload) const {
    if (payload == nullptr) {
        return;
    }

    payload->set_snapshot_id(snapshot.meta.snapshot_id);
    payload->set_app_code(snapshot.app_info.app_code);
    payload->set_policy_version(snapshot.app_info.policy_version);
    payload->set_published_by(snapshot.meta.published_by);
    payload->set_publish_note(snapshot.meta.publish_note);
    payload->set_created_at(snapshot.meta.created_at);
    payload->set_snapshot_json(snapshot_json);

    payload->set_role_count(static_cast<int32_t>(snapshot.roles.size()));
    payload->set_permission_count(static_cast<int32_t>(snapshot.permissions.size()));
    payload->set_role_permission_binding_count(
        static_cast<int32_t>(snapshot.role_permission_bindings.size()));
    payload->set_user_role_binding_count(
        static_cast<int32_t>(snapshot.user_role_bindings.size()));
    payload->set_resource_owner_count(
        static_cast<int32_t>(snapshot.resource_owners.size()));
}

// ======================================================
// fillLocalSnapshotStatus
// 作用：填充当前本地快照状态
// ======================================================
void AgentServiceImpl::fillLocalSnapshotStatus(
    ny::agent::LocalSnapshotStatus* status) const {
    if (status == nullptr) {
        return;
    }

    if (!local_snapshot_engine_) {
        status->set_has_snapshot(false);
        status->set_app_code("");
        status->set_snapshot_id(0);
        status->set_policy_version(0);
        status->set_source_text("LOCAL_SNAPSHOT");
        return;
    }

    status->set_has_snapshot(local_snapshot_engine_->HasSnapshot());
    status->set_app_code(local_snapshot_engine_->CurrentAppCode());
    status->set_snapshot_id(local_snapshot_engine_->CurrentSnapshotId());
    status->set_policy_version(local_snapshot_engine_->CurrentPolicyVersion());
    status->set_source_text("LOCAL_SNAPSHOT");
}

// ======================================================
// fillLocalCheckResponse
// 作用：把本地引擎结果填进 proto 响应
//
// 规则：
// - status.success = false:
//     SNAPSHOT_NOT_READY / INVALID_ARGUMENT / INTERNAL_ERROR
// - 其余情况：
//     status.success = true，具体 allow/deny 看 allowed 字段
// ======================================================
void AgentServiceImpl::fillLocalCheckResponse(
    const LocalSnapshotCheckResult& result,
    ny::agent::LocalCheckResponse* response) const {
    if (response == nullptr) {
        return;
    }

    const std::string& deny_code = result.deny_code;

    if (deny_code == "OK") {
        fillAgentOperationStatus(
            true,
            "本地判权完成",
            "OK",
            response->mutable_status());
    } else if (deny_code == "SNAPSHOT_NOT_READY" ||
               deny_code == "INVALID_ARGUMENT" ||
               deny_code == "INTERNAL_ERROR") {
        fillAgentOperationStatus(
            false,
            result.reason.empty() ? "本地判权失败" : result.reason,
            deny_code,
            response->mutable_status());
    } else {
        fillAgentOperationStatus(
            true,
            "本地判权完成",
            "OK",
            response->mutable_status());
    }

    response->set_allowed(result.allowed);
    response->set_reason(result.reason);

    for (const auto& role : result.current_roles) {
        response->add_current_roles(role);
    }

    for (const auto& role : result.suggest_roles) {
        response->add_suggest_roles(role);
    }

    response->set_deny_code(mapLocalDenyCodeToProto(result.deny_code));
    response->set_snapshot_id(result.snapshot_id);
    response->set_policy_version(result.policy_version);
    response->set_decision_source_text(result.decision_source_text);

    auto* trace = response->mutable_trace();
    trace->set_decision_source(
        mapLocalDecisionSourceToProto(result.decision_source_text));
    trace->set_policy_version(result.policy_version);
    trace->set_owner_shortcut_used(result.owner_shortcut_used);
    trace->set_trace_text(result.trace_text);

    for (const auto& role : result.matched_roles) {
        trace->add_matched_roles(role);
    }

    for (const auto& perm : result.matched_permissions) {
        trace->add_matched_permissions(perm);
    }
}

// ======================================================
// mapAgentErrorCodeToProto
// 作用：内部字符串错误码 -> proto AgentErrorCode
// ======================================================
ny::agent::AgentErrorCode AgentServiceImpl::mapAgentErrorCodeToProto(
    const std::string& error_code) const {
    if (error_code == "OK") {
        return ny::agent::AGENT_ERROR_CODE_OK;
    }
    if (error_code == "INVALID_ARGUMENT") {
        return ny::agent::AGENT_ERROR_CODE_INVALID_ARGUMENT;
    }
    if (error_code == "NOT_FOUND") {
        return ny::agent::AGENT_ERROR_CODE_NOT_FOUND;
    }
    if (error_code == "SNAPSHOT_NOT_READY") {
        return ny::agent::AGENT_ERROR_CODE_SNAPSHOT_NOT_READY;
    }
    if (error_code == "INTERNAL_ERROR") {
        return ny::agent::AGENT_ERROR_CODE_INTERNAL_ERROR;
    }
    return ny::agent::AGENT_ERROR_CODE_UNSPECIFIED;
}

// ======================================================
// mapLocalDenyCodeToProto
// 作用：本地判权 deny_code -> auth.proto DenyCode
//
// 说明：
// - SNAPSHOT_NOT_READY 不在 auth.proto 里，所以映射成 UNSPECIFIED
// - 操作层错误会通过 response.status 体现
// ======================================================
ny::auth::DenyCode AgentServiceImpl::mapLocalDenyCodeToProto(
    const std::string& deny_code) const {
    if (deny_code == "OK") {
        return ny::auth::DENY_CODE_OK;
    }
    if (deny_code == "APP_NOT_FOUND") {
        return ny::auth::DENY_CODE_APP_NOT_FOUND;
    }
    if (deny_code == "APP_DISABLED") {
        return ny::auth::DENY_CODE_APP_DISABLED;
    }
    if (deny_code == "PERMISSION_NOT_FOUND") {
        return ny::auth::DENY_CODE_PERMISSION_NOT_FOUND;
    }
    if (deny_code == "USER_HAS_NO_ROLE") {
        return ny::auth::DENY_CODE_USER_HAS_NO_ROLE;
    }
    if (deny_code == "PERMISSION_DENIED") {
        return ny::auth::DENY_CODE_PERMISSION_DENIED;
    }
    if (deny_code == "RESOURCE_NOT_FOUND") {
        return ny::auth::DENY_CODE_RESOURCE_NOT_FOUND;
    }
    if (deny_code == "INVALID_ARGUMENT") {
        return ny::auth::DENY_CODE_INVALID_ARGUMENT;
    }
    if (deny_code == "INTERNAL_ERROR") {
        return ny::auth::DENY_CODE_INTERNAL_ERROR;
    }

    // SNAPSHOT_NOT_READY / 其他未映射值
    return ny::auth::DENY_CODE_UNSPECIFIED;
}

// ======================================================
// mapLocalDecisionSourceToProto
// 作用：把 LOCAL_SNAPSHOT 映射到 auth.proto 的 DecisionSource
//
// 说明：
// - auth.proto 当前没有 LOCAL_SNAPSHOT 枚举
// - 这里映射到 CACHE 作为“本地已加载数据源”的近似表达
// - 更精确来源仍通过 decision_source_text 返回
// ======================================================
ny::auth::DecisionSource AgentServiceImpl::mapLocalDecisionSourceToProto(
    const std::string& decision_source_text) const {
    if (decision_source_text == "LOCAL_SNAPSHOT") {
        return ny::auth::DECISION_SOURCE_CACHE;
    }
    if (decision_source_text == "CACHE") {
        return ny::auth::DECISION_SOURCE_CACHE;
    }
    if (decision_source_text == "DB") {
        return ny::auth::DECISION_SOURCE_DB;
    }
    return ny::auth::DECISION_SOURCE_UNSPECIFIED;
}

// ======================================================
// serializeSnapshotToJson
// 作用：把 PolicySnapshot 转成 JSON 文本
//
// 说明：
// - 这里是 service 层自带的简洁序列化实现
// - 当前用于 SnapshotPayload.snapshot_json 回填
// ======================================================
std::string AgentServiceImpl::serializeSnapshotToJson(
    const PolicySnapshot& snapshot) const {
    std::ostringstream oss;

    oss << "{";

    // app_info
    oss << "\"app_info\":{"
        << "\"app_id\":" << snapshot.app_info.app_id << ","
        << "\"app_code\":\"" << EscapeJsonString(snapshot.app_info.app_code) << "\","
        << "\"enabled\":" << (snapshot.app_info.enabled ? "true" : "false") << ","
        << "\"policy_version\":" << snapshot.app_info.policy_version
        << "},";

    // meta
    oss << "\"meta\":{"
        << "\"snapshot_id\":" << snapshot.meta.snapshot_id << ","
        << "\"published_by\":\"" << EscapeJsonString(snapshot.meta.published_by) << "\","
        << "\"publish_note\":\"" << EscapeJsonString(snapshot.meta.publish_note) << "\","
        << "\"created_at\":\"" << EscapeJsonString(snapshot.meta.created_at) << "\""
        << "},";

    // roles
    oss << "\"roles\":[";
    for (std::size_t i = 0; i < snapshot.roles.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }

        const auto& role = snapshot.roles[i];
        oss << "{"
            << "\"role_id\":" << role.role_id << ","
            << "\"role_key\":\"" << EscapeJsonString(role.role_key) << "\","
            << "\"role_name\":\"" << EscapeJsonString(role.role_name) << "\","
            << "\"description\":\"" << EscapeJsonString(role.description) << "\","
            << "\"is_default\":" << (role.is_default ? "true" : "false") << ","
            << "\"enabled\":" << (role.enabled ? "true" : "false")
            << "}";
    }
    oss << "],";

    // permissions
    oss << "\"permissions\":[";
    for (std::size_t i = 0; i < snapshot.permissions.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }

        const auto& perm = snapshot.permissions[i];
        oss << "{"
            << "\"permission_id\":" << perm.permission_id << ","
            << "\"perm_key\":\"" << EscapeJsonString(perm.perm_key) << "\","
            << "\"perm_name\":\"" << EscapeJsonString(perm.perm_name) << "\","
            << "\"resource_type\":\"" << EscapeJsonString(perm.resource_type) << "\","
            << "\"owner_shortcut_enabled\":"
            << (perm.owner_shortcut_enabled ? "true" : "false") << ","
            << "\"description\":\"" << EscapeJsonString(perm.description) << "\","
            << "\"enabled\":" << (perm.enabled ? "true" : "false")
            << "}";
    }
    oss << "],";

    // role_permission_bindings
    oss << "\"role_permission_bindings\":[";
    for (std::size_t i = 0; i < snapshot.role_permission_bindings.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }

        const auto& item = snapshot.role_permission_bindings[i];
        oss << "{"
            << "\"role_key\":\"" << EscapeJsonString(item.role_key) << "\","
            << "\"perm_key\":\"" << EscapeJsonString(item.perm_key) << "\""
            << "}";
    }
    oss << "],";

    // user_role_bindings
    oss << "\"user_role_bindings\":[";
    for (std::size_t i = 0; i < snapshot.user_role_bindings.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }

        const auto& item = snapshot.user_role_bindings[i];
        oss << "{"
            << "\"user_id\":\"" << EscapeJsonString(item.user_id) << "\","
            << "\"role_key\":\"" << EscapeJsonString(item.role_key) << "\","
            << "\"granted_by\":\"" << EscapeJsonString(item.granted_by) << "\""
            << "}";
    }
    oss << "],";

    // resource_owners
    oss << "\"resource_owners\":[";
    for (std::size_t i = 0; i < snapshot.resource_owners.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }

        const auto& item = snapshot.resource_owners[i];
        oss << "{"
            << "\"resource_type\":\"" << EscapeJsonString(item.resource_type) << "\","
            << "\"resource_id\":\"" << EscapeJsonString(item.resource_id) << "\","
            << "\"resource_name\":\"" << EscapeJsonString(item.resource_name) << "\","
            << "\"owner_user_id\":\"" << EscapeJsonString(item.owner_user_id) << "\","
            << "\"enabled\":" << (item.enabled ? "true" : "false") << ","
            << "\"metadata_text\":\"" << EscapeJsonString(item.metadata_text) << "\""
            << "}";
    }
    oss << "]";

    oss << "}";

    return oss.str();
}
