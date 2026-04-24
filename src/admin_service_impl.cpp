#include "admin_service_impl.h"

#include <brpc/closure_guard.h>
#include <brpc/controller.h>

#include <utility>

namespace {

// ======================================================
// 辅助函数：填充“请求对象为空”错误
// 这样可以减少各个 RPC 方法里的重复代码
// ======================================================
void FillNullRequestStatus(ny::admin::OperationStatus* status) {

    if(status == nullptr) {

        return;
    }

    status->set_success(false);
    status->set_message("请求对象为空");
    status->set_error_code(ny::admin::ADMIN_ERROR_CODE_INVALID_ARGUMENT);
}

// ======================================================
// 辅助函数：填充“AdminManager 未初始化”错误
// ======================================================
void FillManagerNotReadyStatus(ny::admin::OperationStatus* status) {

    if(status == nullptr) {

        return;
    }

    status->set_success(false);
    status->set_message("系统内部错误：AdminManager 未初始化");
    status->set_error_code(ny::admin::ADMIN_ERROR_CODE_INTERNAL_ERROR);
}

}

// ======================================================
// 构造函数
// ======================================================
AdminServiceImpl::AdminServiceImpl(std::shared_ptr<AdminManager> admin_manager) : admin_manager_(std::move(admin_manager)) {}

// ======================================================
// Login
// ======================================================
void AdminServiceImpl::Login(google::protobuf::RpcController* cntl, const ny::admin::LoginRequest* request, ny::admin::LoginResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerLoginRequest internal_request = buildLoginRequest(*request);
    ManagerLoginResult result = admin_manager_->Login(internal_request);
    fillLoginResponse(result, response);
}

// ======================================================
// CreateRole
// ======================================================
void AdminServiceImpl::CreateRole(google::protobuf::RpcController* cntl, const ny::admin::CreateRoleRequest* request, ny::admin::CreateRoleResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerCreateRoleRequest internal_request = buildCreateRoleRequest(*request);
    ManagerCreateRoleResult result = admin_manager_->CreateRole(internal_request);
    fillCreateRoleResponse(result, response);
}

// ======================================================
// CreatePermission
// ======================================================
void AdminServiceImpl::CreatePermission(google::protobuf::RpcController* cntl, const ny::admin::CreatePermissionRequest* request, ny::admin::CreatePermissionResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerCreatePermissionRequest internal_request = buildCreatePermissionRequest(*request);

    ManagerCreatePermissionResult result = admin_manager_->CreatePermission(internal_request);

    fillCreatePermissionResponse(result, response);
}

// ======================================================
// BindPermissionToRole
// ======================================================
void AdminServiceImpl::BindPermissionToRole(google::protobuf::RpcController* cntl, const ny::admin::BindPermissionToRoleRequest* request, ny::admin::BindPermissionToRoleResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerBindPermissionToRoleRequest internal_request = buildBindPermissionToRoleRequest(*request);

    ManagerBindPermissionToRoleResult result = admin_manager_->BindPermissionToRole(internal_request);

    fillBindPermissionToRoleResponse(result, response);
}

// ======================================================
// GrantRoleToUser
// ======================================================
void AdminServiceImpl::GrantRoleToUser(google::protobuf::RpcController* cntl, const ny::admin::GrantRoleToUserRequest* request, ny::admin::GrantRoleToUserResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerGrantRoleToUserRequest internal_request = buildGrantRoleToUserRequest(*request);

    ManagerGrantRoleToUserResult result = admin_manager_->GrantRoleToUser(internal_request);

    fillGrantRoleToUserResonse(result, response);
}

// ======================================================
// SetResourceOwner
// ======================================================
void AdminServiceImpl::SetResourceOwner(google::protobuf::RpcController* cntl, const ny::admin::SetResourceOwnerRequest* request, ny::admin::SetResourceOwnerResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerSetResourceOwnerRequest internal_request = buildSetResourceOwnerRequest(*request);

    ManagerSetResourceOwnerResult result = admin_manager_->SetResourceOwner(internal_request);

    fillSetResourceOwnerResponse(result, response);
}

// ======================================================
// PublishPolicy
// ======================================================
void AdminServiceImpl::PublishPolicy(google::protobuf::RpcController* cntl, const ny::admin::PublishPolicyRequest* request, ny::admin::PublishPolicyResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerPublishPolicyRequest internal_request = buildPublishPolicyRequest(*request);

    ManagerPublishPolicyResult result = admin_manager_->PublishPolicy(internal_request);

    fillPublishPolicyResponse(result, response);
}

// ======================================================
// SimulateCheck
// ======================================================
void AdminServiceImpl::SimulateCheck(google::protobuf::RpcController* cntl, const ny::admin::SimulateCheckRequest* request, ny::admin::SimulateCheckResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerSimulateCheckRequest internal_request = buildSimulateCheckRequest(*request);

    ManagerSimulateCheckResult result = admin_manager_->SimulateCheck(internal_request);

    fillSimulateCheckResponse(result, response);
}

// ======================================================
// ListAuditLogs
// ======================================================
void AdminServiceImpl::ListAuditLogs(google::protobuf::RpcController* cntl, const ny::admin::ListAuditLogsRequest* request, ny::admin::ListAuditLogsResponse* response, google::protobuf::Closure* done) {

    brpc::ClosureGuard done_guard(done);

    brpc::Controller* brpc_cntl = static_cast<brpc::Controller*>(cntl);

    (void)brpc_cntl;

    if(response == nullptr) {

        return ;
    }

    if(request == nullptr) {

        FillNullRequestStatus(response->mutable_status());

        return ;
    }

    if(!admin_manager_) {

        FillManagerNotReadyStatus(response->mutable_status());

        return ;
    }

    ManagerListAuditLogsRequest internal_request = buildListAuditLogsRequest(*request);

    ManagerListAuditLogsResult result = admin_manager_->ListAuditLogs(internal_request);

    fillListAuditLogsResponse(result, response);
}

// ======================================================
// buildLoginRequest
// ======================================================
ManagerLoginRequest AdminServiceImpl::buildLoginRequest(const ny::admin::LoginRequest& request) const {

    ManagerLoginRequest internal_request;

    internal_request.username = request.username();

    internal_request.password = request.password();

    return internal_request;
}

// ======================================================
// buildCreateRoleRequest
// ======================================================
ManagerCreateRoleRequest AdminServiceImpl::buildCreateRoleRequest(const ny::admin::CreateRoleRequest& request) const {

    ManagerCreateRoleRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.role_key = request.role_key();
    internal_request.role_name = request.role_name();
    internal_request.description = request.description();
    internal_request.is_default = request.is_default();

    return internal_request;
}

// ======================================================
// buildCreatePermissionRequest
// ======================================================
ManagerCreatePermissionRequest AdminServiceImpl::buildCreatePermissionRequest(const ny::admin::CreatePermissionRequest& request) const {

    ManagerCreatePermissionRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.perm_key = request.perm_key();
    internal_request.perm_name = request.perm_name();
    internal_request.resource_type = request.resource_type();
    internal_request.owner_shortcut_enabled = request.owner_shortcut_enabled();
    internal_request.description = request.description();

    return internal_request;
}

// ======================================================
// buildBindPermissionToRoleRequest
// ======================================================
ManagerBindPermissionToRoleRequest AdminServiceImpl::buildBindPermissionToRoleRequest(const ny::admin::BindPermissionToRoleRequest& request) const {

    ManagerBindPermissionToRoleRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.role_key = request.role_key();
    internal_request.perm_key = request.perm_key();

    return internal_request;
}

// ======================================================
// buildGrantRoleToUserRequest
// ======================================================
ManagerGrantRoleToUserRequest AdminServiceImpl::buildGrantRoleToUserRequest(const ny::admin::GrantRoleToUserRequest& request) const {

    ManagerGrantRoleToUserRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.user_id = request.user_id();
    internal_request.role_key = request.role_key();

    return internal_request;
}

// ======================================================
// buildSetResourceOwnerRequest
// ======================================================
ManagerSetResourceOwnerRequest AdminServiceImpl::buildSetResourceOwnerRequest(const ny::admin::SetResourceOwnerRequest& request) const {

    ManagerSetResourceOwnerRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.resource_type = request.resource_type();
    internal_request.resource_id = request.resource_id();
    internal_request.resource_name = request.resource_name();
    internal_request.owner_user_id = request.owner_user_id();
    internal_request.metadata_text = request.metadata_text();

    return internal_request;
}

// ======================================================
// buildPublishPolicyRequest
// ======================================================
ManagerPublishPolicyRequest AdminServiceImpl::buildPublishPolicyRequest(const ny::admin::PublishPolicyRequest& request) const{

    ManagerPublishPolicyRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.publish_note = request.publish_note();

    return internal_request;
}

// ======================================================
// buildSimulateCheckRequest
// ======================================================
ManagerSimulateCheckRequest AdminServiceImpl::buildSimulateCheckRequest(const ny::admin::SimulateCheckRequest& request) const {

    ManagerSimulateCheckRequest internal_request;

    internal_request.operator_token = request.operator_token();

    SimulationRequest simulation_request;

    simulation_request.app_code = request.app_code();
    simulation_request.user_id = request.user_id();
    simulation_request.perm_key = request.perm_key();
    simulation_request.resource_type = request.resource_type();
    simulation_request.resource_id = request.resource_id();
    simulation_request.request_id = request.request_id();

    for(int i = 0 ; i < request.simulated_grants_size(); i++) {

        const auto& grant = request.simulated_grants(i);

        SimulatedGrantRole item;
        
        item.user_id = grant.user_id();
        item.role_key = grant.role_key();

        simulation_request.simulated_grants.push_back(item);
    }

    for(int i = 0; i < request.simulated_bindings_size(); i++) {

        const auto& binding = request.simulated_bindings(i);

        SimulateBindPermission item;

        item.role_key = binding.role_key();
        item.perm_key = binding.perm_key();

        simulation_request.simulated_bindings.push_back(item);
    }

    for(int i = 0; i < request.simulated_owner_overrides_size(); i++) {

        const auto& owner_override = request.simulated_owner_overrides(i);

        SimulatedOwnerOverride item;

        item.resource_type = owner_override.resource_type();
        item.resource_id = owner_override.resource_id();
        item.owner_user_id = owner_override.owner_user_id();

        simulation_request.simulated_owner_overrides.push_back(item);
    }
    internal_request.simulation_request = simulation_request;

    return internal_request;
}

// ======================================================
// buildListAuditLogsRequest
// ======================================================
ManagerListAuditLogsRequest AdminServiceImpl::buildListAuditLogsRequest(const ny::admin::ListAuditLogsRequest& request) const {

    ManagerListAuditLogsRequest internal_request;

    internal_request.operator_token = request.operator_token();
    internal_request.app_code = request.app_code();
    internal_request.action_type = request.action_type();
    internal_request.limit = request.limit();

    return internal_request;
}

// ======================================================
// fillLoginResponse
// ======================================================
void AdminServiceImpl::fillLoginResponse(const ManagerLoginResult& result, ny::admin::LoginResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());

    if(result.status.success) {

        auto* session = response->mutable_session();

        session->set_token(result.session.token);
        session->set_user_id(result.session.user_id);
        session->set_username(result.session.username);
        session->set_display_name(result.session.display_name);
        session->set_is_super_admin(result.session.is_super_admin);
        session->set_expires_in_seconds(result.expires_in_seconds);
    }
}

// ======================================================
// fillCreateRoleResponse
// ======================================================
void AdminServiceImpl::fillCreateRoleResponse(const ManagerCreateRoleResult& result, ny::admin::CreateRoleResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());

    response->set_role_id(result.role_id);
}

// ======================================================
// fillCreatePermissionResponse
// ======================================================
void AdminServiceImpl::fillCreatePermissionResponse(const ManagerCreatePermissionResult& result, ny::admin::CreatePermissionResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());

    response->set_permission_id(result.permission_id);
}

// ======================================================
// fillBindPermissionToRoleResponse
// ======================================================
void AdminServiceImpl::fillBindPermissionToRoleResponse(const ManagerBindPermissionToRoleResult& result, ny::admin::BindPermissionToRoleResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());
} 

// ======================================================
// fillGrantRoleToUserResponse
// ======================================================
void AdminServiceImpl::fillGrantRoleToUserResonse(const ManagerGrantRoleToUserResult& result, ny::admin::GrantRoleToUserResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());
}

// ======================================================
// fillSetResourceOwnerResponse
// ======================================================
void AdminServiceImpl::fillSetResourceOwnerResponse(const ManagerSetResourceOwnerResult& result, ny::admin::SetResourceOwnerResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());
}

// ======================================================
// fillPublishPolicyResponse
// ======================================================
void AdminServiceImpl::fillPublishPolicyResponse(const ManagerPublishPolicyResult& result, ny::admin::PublishPolicyResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());
    
    response->set_new_policy_version(result.new_policy_version);
}

// ======================================================
// fillSimulateCheckResponse
// ======================================================
void AdminServiceImpl::fillSimulateCheckResponse(const ManagerSimulateCheckResult& result, ny::admin::SimulateCheckResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());

    response->set_allowed(result.simulation_result.allowed);
    response->set_reason(result.simulation_result.reason);
    response->set_deny_code(mapDenyCodeToProto(result.simulation_result.deny_code));

    for(const auto& role : result.simulation_result.current_roles) {

        response->add_current_roles(role);
    }

    for(const auto& role : result.simulation_result.suggest_roles) {

        response->add_suggest_roles(role);
    }

    auto* trace = response->mutable_trace();

    trace->set_decision_source(mapSimulationDecisionSourceToProto(result.simulation_result.decision_source_text));
    trace->set_policy_version(result.simulation_result.policy_version);
    trace->set_owner_shortcut_used(result.simulation_result.owner_shortcut_used);
    trace->set_trace_text(result.simulation_result.trace_text);

    for(const auto& role : result.simulation_result.matched_roles) {

        trace->add_matched_roles(role);
    }
    
    for(const auto& perm : result.simulation_result.matched_permissions) {

        trace->add_matched_permissions(perm);
    }
}

// ======================================================
// fillListAuditLogsResponse
// ======================================================
void AdminServiceImpl::fillListAuditLogsResponse(const ManagerListAuditLogsResult& result, ny::admin::ListAuditLogsResponse* response) const {

    if(response == nullptr) {

        return ;
    }

    fillOperationStatus(result.status, response->mutable_status());

    for(const auto& item : result.items) {

        auto* proto_item = response->add_items();

        proto_item->set_id(item.id);
        proto_item->set_operator_user_id(item.operator_user_id);
        proto_item->set_operator_username(item.operator_username);
        proto_item->set_operator_display_name(item.operator_display_name);
        proto_item->set_app_code(item.app_code);
        proto_item->set_action_type(item.action_type);
        proto_item->set_target_type(item.target_type);
        proto_item->set_target_key(item.target_key);
        proto_item->set_before_text(item.before_text);
        proto_item->set_after_text(item.after_text);
        proto_item->set_trace_text(item.trace_text);
        proto_item->set_created_at(item.created_at);
    }
}

// ======================================================
// fillOperationStatus
// ======================================================
void AdminServiceImpl::fillOperationStatus(const AdminOperationStatus& status, ny::admin::OperationStatus* proto_status) const {

    if(proto_status == nullptr) {

        return ;
    }

    proto_status->set_success(status.success);
    proto_status->set_message(status.message);
    proto_status->set_error_code(mapAdminErrorCodeToProto(status.error_code));
}

// ======================================================
// mapAdminErrorCodeToProto
// ======================================================
ny::admin::AdminErrorCode AdminServiceImpl::mapAdminErrorCodeToProto(const std::string& error_code) const {

    if(error_code == "OK") {

        return ny::admin::ADMIN_ERROR_CODE_OK;
    }

    if(error_code == "INVALID_ARGUMENT") {

        return ny::admin::ADMIN_ERROR_CODE_INVALID_ARGUMENT;
    }

    if(error_code == "UNAUTHORIZED") {

        return ny::admin::ADMIN_ERROR_CODE_UNAUTHORIZED;
    }

    if(error_code == "FORBIDDEN") {

        return ny::admin::ADMIN_ERROR_CODE_FORBIDDEN;
    }

    if(error_code == "NOT_FOUND") {

        return ny::admin::ADMIN_ERROR_CODE_NOT_FOUND;
    }

    if(error_code == "ALREADY_EXISTS") {

        return ny::admin::ADMIN_ERROR_CODE_ALREADY_EXISTS;
    }

    if(error_code == "CONFLICT") {

        return ny::admin::ADMIN_ERROR_CODE_CONFLICT;
    }

    if(error_code == "INTERNAL_ERROR") {

        return ny::admin::ADMIN_ERROR_CODE_INTERNAL_ERROR;
    }

    return ny::admin::ADMIN_ERROR_CODE_UNSPECIFIED;
}

// ======================================================
// mapDenyCodeToProto
// ======================================================
ny::auth::DenyCode AdminServiceImpl::mapDenyCodeToProto(const std::string& deny_code) const {

    if(deny_code == "APP_COT_FOUND") {

        return ny::auth::DENY_CODE_APP_NOT_FOUND;
    }

    if(deny_code == "APP_DISABLED") {

        return ny::auth::DENY_CODE_APP_DISABLED;
    }

    if(deny_code == "PERMISSION_COT_FOUND") {

        return ny::auth::DENY_CODE_PERMISSION_NOT_FOUND;
    }

    if(deny_code == "USER_HAS_NO_ROLE") {

        return ny::auth::DENY_CODE_USER_HAS_NO_ROLE;
    }

    if(deny_code == "PERMISSION_DENIED") {

        return ny::auth::DENY_CODE_PERMISSION_DENIED;
    }

    if(deny_code == "RESOURCE_NOT_FOUND") {

        return ny::auth::DENY_CODE_RESOURCE_NOT_FOUND;
    }

    // if(deny_code == "OWNER_SHORTCUT_DISABLED") {

    //     return ny::auth::DENY_CODE_OWNER_SHORTCUT_DISABLED;
    // }

    if(deny_code == "INVALID_ARGUMENT") {

        return ny::auth::DENY_CODE_INVALID_ARGUMENT;
    }

    if(deny_code == "INTERNAL_ERROR") {

        return ny::auth::DENY_CODE_INTERNAL_ERROR;
    }

    return ny::auth::DENY_CODE_UNSPECIFIED;
}

// ======================================================
// mapSimulationDecisionSourceToProto
// ======================================================
ny::auth::DecisionSource AdminServiceImpl::mapSimulationDecisionSourceToProto(const std::string& decision_source_text) const {

    if(decision_source_text == "LIVE_DB_WITH_SIMULATION") {

        return ny::auth::DECISION_SOURCE_DB;
    }

    if(decision_source_text == "DB") {

        return ny::auth::DECISION_SOURCE_DB;
    }

    if(decision_source_text == "CACHE") {

        return ny::auth::DECISION_SOURCE_CACHE;
    }

    return ny::auth::DECISION_SOURCE_UNSPECIFIED;
}
