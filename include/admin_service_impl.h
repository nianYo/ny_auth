#ifndef NY_AUTH_ADMIN_SERVICE_IMPL_H
#define NY_AUTH_ADMIN_SERVICE_IMPL_H

#include <memory>

#include <string>

#include <google/protobuf/stubs/callback.h>
#include <google/protobuf/service.h>

#include "admin.pb.h"

#include "admin_manager.h"

// ======================================================
// AdminServiceImpl
// 作用：
// 1. 继承 proto 中定义的 ny::admin::AdminService
// 2. 接收管理端 RPC 请求
// 3. 把 proto 请求转换成 AdminManager 的内部请求对象
// 4. 调用 AdminManager 执行真正管理逻辑
// 5. 把内部结果转换回 proto 响应
// ======================================================
class AdminServiceImpl : public ny::admin::AdminService {
public:

    explicit AdminServiceImpl(std::shared_ptr<AdminManager> admin_manager);

    void Login(google::protobuf::RpcController* cntl, const ny::admin::LoginRequest* request, ny::admin::LoginResponse* response, google::protobuf::Closure* done) override;

    void CreateRole(google::protobuf::RpcController* cntl, const ny::admin::CreateRoleRequest* request, ny::admin::CreateRoleResponse* response, google::protobuf::Closure* done) override;

    void CreatePermission(google::protobuf::RpcController* cntl, const ny::admin::CreatePermissionRequest* request, ny::admin::CreatePermissionResponse* response, google::protobuf::Closure* done) override;

    void BindPermissionToRole(google::protobuf::RpcController* cntl, const ny::admin::BindPermissionToRoleRequest* request, ny::admin::BindPermissionToRoleResponse* response, google::protobuf::Closure* done) override;

    void GrantRoleToUser(google::protobuf::RpcController* cntl, const ny::admin::GrantRoleToUserRequest* request, ny::admin::GrantRoleToUserResponse* response, google::protobuf::Closure* done) override;

    void SetResourceOwner(google::protobuf::RpcController* cntl, const ny::admin::SetResourceOwnerRequest* request, ny::admin::SetResourceOwnerResponse* response, google::protobuf::Closure* done) override;

    void PublishPolicy(google::protobuf::RpcController* cntl, const ny::admin::PublishPolicyRequest* request, ny::admin::PublishPolicyResponse* response, google::protobuf::Closure* done) override;

    void SimulateCheck(google::protobuf::RpcController* cntl, const ny::admin::SimulateCheckRequest* request, ny::admin::SimulateCheckResponse* response, google::protobuf::Closure* done) override;

    void ListAuditLogs(google::protobuf::RpcController* cntl, const ny::admin::ListAuditLogsRequest* request, ny::admin::ListAuditLogsResponse* response, google::protobuf::Closure* done) override;

private:

    ManagerLoginRequest buildLoginRequest(const ny::admin::LoginRequest& request) const;

    ManagerCreateRoleRequest buildCreateRoleRequest(const ny::admin::CreateRoleRequest& request) const;

    ManagerCreatePermissionRequest buildCreatePermissionRequest(const ny::admin::CreatePermissionRequest& request) const;

    ManagerBindPermissionToRoleRequest buildBindPermissionToRoleRequest(const ny::admin::BindPermissionToRoleRequest& request) const;

    ManagerGrantRoleToUserRequest buildGrantRoleToUserRequest(const ny::admin::GrantRoleToUserRequest& request) const;

    ManagerSetResourceOwnerRequest buildSetResourceOwnerRequest(const ny::admin::SetResourceOwnerRequest& request) const;

    ManagerPublishPolicyRequest buildPublishPolicyRequest(const ny::admin::PublishPolicyRequest& request) const;

    ManagerSimulateCheckRequest buildSimulateCheckRequest(const ny::admin::SimulateCheckRequest& request) const;

    ManagerListAuditLogsRequest buildListAuditLogsRequest(const ny::admin::ListAuditLogsRequest& request) const;

    void fillLoginResponse(const ManagerLoginResult& result, ny::admin::LoginResponse* response) const;

    void fillCreateRoleResponse(const ManagerCreateRoleResult& result, ny::admin::CreateRoleResponse* response) const;

    void fillCreatePermissionResponse(const ManagerCreatePermissionResult& result, ny::admin::CreatePermissionResponse* response) const;

    void fillBindPermissionToRoleResponse(const ManagerBindPermissionToRoleResult& result, ny::admin::BindPermissionToRoleResponse* response) const;

    void fillGrantRoleToUserResonse(const ManagerGrantRoleToUserResult& result, ny::admin::GrantRoleToUserResponse* response) const;

    void fillSetResourceOwnerResponse(const ManagerSetResourceOwnerResult& result, ny::admin::SetResourceOwnerResponse* response) const;

    void fillPublishPolicyResponse(const ManagerPublishPolicyResult& result, ny::admin::PublishPolicyResponse* response) const;

    void fillSimulateCheckResponse(const ManagerSimulateCheckResult& result, ny::admin::SimulateCheckResponse* response) const;

    void fillListAuditLogsResponse(const ManagerListAuditLogsResult& result, ny::admin::ListAuditLogsResponse* response) const;

    void fillOperationStatus(const AdminOperationStatus& status, ny::admin::OperationStatus* proto_status) const;

    ny::admin::AdminErrorCode mapAdminErrorCodeToProto(const std::string& error_code) const;

    ny::auth::DenyCode mapDenyCodeToProto(const std::string& deny_code) const;

    ny::auth::DecisionSource mapSimulationDecisionSourceToProto(const std::string& decision_source_text) const;

private:

    std::shared_ptr<AdminManager> admin_manager_;
};

#endif