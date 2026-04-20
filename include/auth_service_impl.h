#ifndef NY_AUTH_SERVICE_IMPL_H
#define NY_AUTH_SERVICE_IMPL_H

#include <memory>

#include <string>

#include <google/protobuf/stubs/callback.h>
#include <google/protobuf/service.h>

#include "auth.pb.h"

#include "decision_engine.h"

// ======================================================
// AuthServiceImpl
// 作用：
// 1. 继承 proto 里定义的 ny::auth::AuthService
// 2. 接收外部 RPC 请求
// 3. 把 proto 请求转成内部 DecisionRequest
// 4. 调用 DecisionEngine 做判断
// 5. 把 DecisionResult 填回 proto 响应
// ======================================================
class AuthServiceImpl : public ny::auth::AuthService {
public:

    explicit AuthServiceImpl(std::shared_ptr<DecisionEngine> engine);

    void Check(google::protobuf::RpcController* cntl, const ny::auth::CheckRequest* request, ny::auth::CheckResponse* response, google::protobuf::Closure* done) override;

private:

    DecisionRequest buildDecisionRequest(const ny::auth::CheckRequest& request) const;

    void fillCheckResponse(const DecisionResult& result, ny::auth::CheckResponse* response) const;

    ny::auth::DecisionSource mapDecisionSourceToProto(DecisionSourceType source) const;

    ny::auth::DenyCode mapDenyCodeToProto(const std::string& deny_code) const;

private:

    std::shared_ptr<DecisionEngine> engine_;
};

#endif