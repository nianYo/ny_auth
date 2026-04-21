#include<memory>

#include <butil/logging.h>

#include <gflags/gflags.h>

#include <brpc/server.h>

#include "local_cache.h"

#include "permission_dao.h"

#include "decision_engine.h"

#include"auth_service_impl.h"

DEFINE_int32(port, 8001, "ny_auth sever port");

DEFINE_string(db_host, "127.0.0.1", "MySQL host");

DEFINE_int32(db_port, 3306, "MySQL port");

DEFINE_string(db_user, "root", "MySQL user");

DEFINE_string(db_password, "zk041125", "MySQL password");

DEFINE_string(db_name, "ny_auth", "MySQL database name");

DEFINE_int32(cache_ttl, 60, "permission cache ttl in seconds");

int main(int argc, char* argv[]) {

    gflags::ParseCommandLineFlags(&argc, &argv, true);

    using UserPermSet = std::unordered_set<std::string>;

    auto cache = std::make_shared<LocalCache<UserPermSet>>();

    auto dao =std::make_shared<PermissionDAO>(FLAGS_db_host, FLAGS_db_port, FLAGS_db_user, FLAGS_db_password, FLAGS_db_name);

    if(!dao->isConnected()) {
        
        LOG(ERROR) << "数据库连接失败，host = " << FLAGS_db_host << ", port = " << FLAGS_db_port << ", db = " << FLAGS_db_name << ", last_error = " << dao->getLastError();

        return -1;
    }

    auto engine = std::make_shared<DecisionEngine>(cache, dao, FLAGS_cache_ttl);

    AuthServiceImpl auth_service(engine);

    brpc::Server server;

    if(server.AddService(&auth_service, brpc::SERVER_DOESNT_OWN_SERVICE) != 0) {
        
        LOG(ERROR) <<"AddService 失败";
        
        return -1;
    }

    brpc::ServerOptions options;

    if(server.Start(FLAGS_port, &options) != 0) {
        
        LOG(ERROR) << "服务启动失败，port = " << FLAGS_port;
        
        return -1;
    }

    LOG(INFO) << "ny_auth 启动成功" << ", port = " << FLAGS_port << ", db_host = " << FLAGS_db_host << ", db_port = " << FLAGS_db_port << ", db_name = " << FLAGS_db_name << ", cache_ttl = " << FLAGS_cache_ttl;

    server.RunUntilAskedToQuit();

    return 0;
}