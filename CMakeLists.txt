cmake_minimum_required(VERSION 3.10)

project(ny_auth)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(Threads REQUIRED)

find_package(Protobuf REQUIRED)

find_package(PkgConfig REQUIRED)

pkg_check_modules(BRPC REQUIRED brpc)

find_path(MYSQL_INCLUDE_DIR mysql_driver.h)
find_library(MYSQL_LIBRARY mysqlcppconn)

find_library(GFLAGS_LIBRARY gflags)

if(NOT MYSQL_INCLUDE_DIR OR NOT MYSQL_LIBRARY)
    message(FATAL_ERROR "mysqlcppconn not found")
endif()

if(NOT GFLAGS_LIBRARY)
    message(FATAL_ERROR "gflags libiary not found")
endif()

set(PROTO_SRCS src/auth.pb.cc)
set(PROTO_HDRS src/auth.pb.h)

add_executable(auth_server src/server_main.cpp src/permission_dao.cpp src/decision_engine.cpp src/auth_service_impl.cpp ${PROTO_SRCS})

target_include_directories(auth_server PRIVATE include src ${PROTOBUF_INCLUDE_DIRS} ${BRPC_INCLUDE_DIRS} ${MYSQL_INCLUDE_DIR})

target_link_libraries(auth_server ${PROTOBUF_LIBRARIES} ${BRPC_LIBRARIES} ${MYSQL_LIBRARY} ${GFLAGS_LIBRARY} Threads::Threads pthread dl z ssl crypto leveldb)

message(STATUS "Project name: ${PROJECT_NAME}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Protobuf includes: ${PROTOBUF_INCLUDE_DIRS}")
message(STATUS "BRPC includes: ${BRPC_INCLUDE_DIRS}")
message(STATUS "MySQL include dir: ${MYSQL_INCLUDE_DIR}")
message(STATUS "MySQL library: ${MYSQL_LIBRARY}")
message(STATUS "gflags library: ${GFLAGS_LIBRARY}")