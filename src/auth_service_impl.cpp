#include "auth_service_impl.h"

#include <brpc/closure_guard.h>
#include <brpc/controller.h>

#include <utility>

namespace {

// ======================================================
// FillInvalidArgumentResponse
// 作用：快速填充“参数错误”响应
// ======================================================
void FillInvalArgumentResponse(ny::auth::CheckResponse* response, const std::string& reason) {

    if(response == nullptr) {
        return;
    }

    response->set_allowed(false);

    response->set_reason(reason);

    response->set_deny_code(ny::auth::DENY_CODE_INVALID_ARGUMENT);

    ny::auth::DecisionTrace* trace = response->mutable_trace();
    trace->set_owner_shortcut_used(false);
    trace->set_policy_version(1);
    trace->set_decision_source(ny::auth::DECISION_SOURCE_UNSPECIFIED);
    trace->set_trace_text("auth request invalid");
}

// ======================================================
// FillInternalErrorResponse
// 作用：快速填充“系统内部错误”响应
// ======================================================
void FillInternalErrorResonse(ny::auth::CheckResponse* response, const std::string& reason) {

    if(response == nullptr) {
        return;
    }
    
    response->set_allowed(false);
    response->set_reason(reason);
    response->set_deny_code(ny::auth::DENY_CODE_INTERNAL_ERROR);

    ny::auth::DecisionTrace* trace = response->mutable_trace();
    trace->set_owner_shortcut_used(false);
    trace->set_policy_version(1);
    trace->set_decision_source(ny::auth::DECISION_SOURCE_UNSPECIFIED);
    trace->set_trace_text("auth service internal error");
}

}

// ======================================================
// 构造函数
// 作用：保存已经创建好的决策引擎
// ======================================================
AuthServiceImpl::AuthServiceImpl(std::shared_ptr<DecisionEngine> engine) : engine_(std::move(engine)) {}

// ======================================================
// Check
// 作用：
// 1. 接收外部 RPC 请求
// 2. 把 proto 请求转换成内部 DecisionRequest
// 3. 调用 DecisionEngine 做权限判断
// 4. 把 DecisionResult 填充回 proto 响应
// ======================================================
void AuthServiceImpl::Check(google::protobuf::RpcController* cntl, const ny::auth::CheckRequest*request, ny::auth::CheckResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);
    (void)brpc_cntl;

    if(response == nullptr) {
        return ;
    }

    if(request == nullptr) {

        FillInvalArgumentResponse(response, "请求对象为空");
        return ;
    }

    if(!engine_) {

        FillInternalErrorResonse(response, "系统内部的错误：DecisionEngine 未初始化");
        return ;
    }

    const DecisionRequest internal_request = buildDecisionRequest(*request);

    try {

        const DecisionResult result = engine_->Evaluate(internal_request);

        fillCheckResponse(result, response);
    } catch (const std::exception& e) {

        FillInternalErrorResonse(response, std::string("鉴权执行异常：") + e.what());
    } catch (...) {

        FillInternalErrorResonse(response, "鉴权执行异常，未知错误");
    }
}

// ======================================================
// buildDecisionRequest
// 作用：把 proto 的 CheckRequest 转成内部的 DecisionRequest
// ======================================================
DecisionRequest AuthServiceImpl::buildDecisionRequest(const ny::auth::CheckRequest& request) const {

    DecisionRequest internal_request;

    internal_request.app_code = request.app_code();

    internal_request.user_id = request.user_id();

    internal_request.perm_key = request.perm_key();

    internal_request.resource_type = request.resource_type();

    internal_request.resource_id = request.resource_id();

    internal_request.request_id = request.request_id();

    return internal_request;
}

// ======================================================
// fillCheckResponse
// 作用：把内部 DecisionResult 填充到 proto CheckResponse
// ======================================================
void AuthServiceImpl::fillCheckResponse(const DecisionResult& result, ny::auth::CheckResponse* response) const {

    if(response == nullptr) {
        return ;
    }

    response->set_allowed(result.allowed);

    response->set_reason(result.reason);

    response->set_deny_code(mapDenyCodeToProto(result.deny_code));

    for(const auto& role : result.current_roles) {
        
        response->add_current_roles(role);
    }

    for(const auto& role : result.suggest_roles) {
        
        response->add_suggest_roles(role);
    }

    ny::auth::DecisionTrace* trace = response->mutable_trace();

    for(const auto& role : result.matched_roles) {
        
        trace->add_matched_roles(role);
    }

    for(const auto& perm : result.matched_permissions) {
        
        trace->add_matched_permissions(perm);
    }

    trace->set_owner_shortcut_used(result.owner_shortcut_used);

    trace->set_policy_version(result.policy_version);

    trace->set_decision_source(mapDecisionSourceToProto(result.decision_source));

    trace->set_trace_text(result.trace_text);
}

// ======================================================
// mapDecisionSourceToProto
// 作用：把内部决策来源枚举映射成 proto 枚举
// ======================================================
ny::auth::DecisionSource AuthServiceImpl::mapDecisionSourceToProto(DecisionSourceType source) const {

    switch(source) {

        case DecisionSourceType::kDatabase:
            return ny::auth::DECISION_SOURCE_DB;

        case DecisionSourceType::kCache:
            return ny::auth::DECISION_SOURCE_CACHE;

        case DecisionSourceType::kUnknown:
        default:
            return ny::auth::DECISION_SOURCE_UNSPECIFIED;

    }
}

// ======================================================
// mapDenyCodeToProto
// 作用：把内部 deny_code 字符串映射成 proto 里的 DenyCode 枚举
// ======================================================
ny::auth::DenyCode AuthServiceImpl::mapDenyCodeToProto(const std::string& deny_code) const {
    
    if(deny_code == "OK") {
        return ny::auth::DENY_CODE_OK;
    }

    if(deny_code == "INVALID_ARGUMENT") {
        return ny::auth::DENY_CODE_INVALID_ARGUMENT;
    }

    if(deny_code == "APP_NOT_FOUND") {
        return ny::auth::DENY_CODE_APP_NOT_FOUND;
    }

    if(deny_code == "APP_DISABLED") {
        return ny::auth::DENY_CODE_APP_DISABLED;
    }

    if(deny_code == "PERMISSION_NOT_FOUND") {
        return ny::auth::DENY_CODE_PERMISSION_NOT_FOUND;
    }

    if(deny_code == "RESOURCE_NOT_FOUND") {
        return ny::auth::DENY_CODE_RESOURCE_NOT_FOUND;
    }

    if(deny_code == "USER_HAS_NO_ROLE") {
        return ny::auth::DENY_CODE_USER_HAS_NO_ROLE;
    }

    if(deny_code == "PERMISSION_DENIED") {
        return ny::auth::DENY_CODE_PERMISSION_DENIED;
    }

    if(deny_code == "INTERNAL_ERROR") {
        return ny::auth::DENY_CODE_INTERNAL_ERROR;
    }

    return ny::auth::DENY_CODE_UNSPECIFIED;
}
