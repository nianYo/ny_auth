#include<memory>

#include <butil/logging.h>

#include <gflags/gflags.h>

#include <brpc/server.h>

#include "local_cache.h"

#include "permission_dao.h"

#include "decision_engine.h"

#include"auth_service_impl.h"

#include "session_types.h"

#include "admin_dao.h"

#include "simulation_engine.h"

#include "admin_manager.h"

#include "admin_service_impl.h"


DEFINE_int32(port, 8001, "ny_auth sever port");

DEFINE_string(db_host, "127.0.0.1", "MySQL host");

DEFINE_int32(db_port, 3306, "MySQL port");

DEFINE_string(db_user, "root", "MySQL user");

DEFINE_string(db_password, "123456", "MySQL password");

DEFINE_string(db_name, "ny_auth", "MySQL database name");

DEFINE_int32(cache_ttl, 60, "permission cache ttl in seconds");

DEFINE_int32(admin_session_ttl, 3600, "admin session ttl, in seconds");

int main(int argc, char* argv[]) {

    gflags::ParseCommandLineFlags(&argc, &argv, true);

    using UserPermSet = std::unordered_set<std::string>;

    using AdminSessionCache = LocalCache<AdminSessionInfo>;

    auto runtime_permission_cache = std::make_shared<LocalCache<UserPermSet>>();

    auto admin_session_cache = std::make_shared<AdminSessionCache>();

    auto permission_dao = std::make_shared<PermissionDAO>(FLAGS_db_host, FLAGS_db_port, FLAGS_db_user, FLAGS_db_password, FLAGS_db_name);

    auto admin_dao = std::make_shared<AdminDAO>(FLAGS_db_host, FLAGS_db_port, FLAGS_db_user, FLAGS_db_password, FLAGS_db_name);

    if(!permission_dao->isConnected()) {
        
        LOG(ERROR) << "PermissionDAO 数据库连接失败，host = " << FLAGS_db_host << ", port = " << FLAGS_db_port << ", db = " << FLAGS_db_name << ", last_error = " << permission_dao->getLastError();

        return -1;
    }

    if(!admin_dao->isConnected()) {
        
        LOG(ERROR) << "AdminDAO 数据库连接失败，host = " << FLAGS_db_host << ", port = " << FLAGS_db_port << ", db = " << FLAGS_db_name << ", last_error = " << admin_dao->getLastError();

        return -1;
    }

    auto decision_engine = std::make_shared<DecisionEngine>(runtime_permission_cache, permission_dao, FLAGS_cache_ttl);

    AuthServiceImpl auth_service(decision_engine);

    auto simulation_enggine = std::make_shared<SimulationEngine>(permission_dao, admin_dao);

    auto admin_manager = std::make_shared<AdminManager>(admin_dao, simulation_enggine, admin_session_cache, FLAGS_admin_session_ttl);

    AdminServiceImpl admin_service(admin_manager);

    brpc::Server server;

    if(server.AddService(&auth_service, brpc::SERVER_DOESNT_OWN_SERVICE) != 0) {
        
        LOG(ERROR) <<"AddService(AuthServiceImpl) 失败";
        
        return -1;
    }

    if(server.AddService(&admin_service, brpc::SERVER_DOESNT_OWN_SERVICE) != 0){

        LOG(ERROR) << "AddService(AdminServiceImpl)失败";

        return -1;
    }

    brpc::ServerOptions options;

    if(server.Start(FLAGS_port, &options) != 0) {
        
        LOG(ERROR) << "服务启动失败，port = " << FLAGS_port;
        
        return -1;
    }

    LOG(INFO) << "ny_auth V2 启动成功" << ", port = " << FLAGS_port << ", db_host = " << FLAGS_db_host << ", db_port = " << FLAGS_db_port << ", db_name = " << FLAGS_db_name << ", cache_ttl = " << FLAGS_cache_ttl;

    server.RunUntilAskedToQuit();

    return 0;
}