# ny_auth

`ny_auth` 是一个基于 **C++ / brpc / Protobuf / MySQL** 的中心化权限鉴权服务。项目面向多业务系统接入场景，提供基于 RBAC 的权限判断、资源 owner 快捷规则、策略版本、权限缓存、决策解释和决策日志能力。

## 功能特性

- **中心化鉴权接口**：通过 `AuthService.Check` 统一判断用户是否拥有某个权限。
- **RBAC 权限模型**：支持“用户 -> 角色 -> 权限”的标准授权链路。
- **资源 owner 快捷规则**：资源所有者可在指定权限上快捷放行，例如文档 owner 可直接读取或编辑自己的文档。
- **可解释决策结果**：返回命中的角色、命中的权限、决策来源、策略版本和 trace 文本，方便排查权限问题。
- **本地 TTL 缓存**：使用应用、用户、策略版本构造权限缓存 key，减少数据库查询。
- **决策日志**：记录每次鉴权结果，便于追踪线上权限判断行为。
- **管理端能力（V2）**：包含管理员登录、创建角色、创建权限、角色绑定权限、用户授权角色、设置资源 owner、发布策略、模拟鉴权和审计日志查询等接口。

## 技术栈

- C++17
- CMake 3.10+
- brpc
- Protobuf
- MySQL / MySQL Connector C++
- gflags
- pthread / OpenSSL / zlib / LevelDB 等 brpc 相关依赖

## 项目结构

```text
ny_auth/
├── CMakeLists.txt
├── include/                 # 业务头文件
│   ├── auth_service_impl.h
│   ├── decision_engine.h
│   ├── local_cache.h
│   └── permission_dao.h
├── proto/
│   └── auth.proto           # AuthService 鉴权接口定义
├── sql/
│   ├── init.sql             # 基础表结构与测试数据
│   └── v2_alter.sql         # V2 管理端表与审计日志表
└── src/                     # 业务实现与生成的 protobuf 文件
    ├── server_main.cpp
    ├── auth_service_impl.cpp
    ├── decision_engine.cpp
    ├── permission_dao.cpp
    ├── admin_service_impl.cpp
    ├── admin_manager.cpp
    ├── admin_dao.cpp
    ├── simulation_engine.cpp
    ├── auth.pb.cc / auth.pb.h
    └── admin.pb.cc / admin.pb.h
```

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/nianYo/ny_auth.git
cd ny_auth
```

### 2. 准备数据库（推荐 Docker 一键启动 MySQL）

项目已提供 `compose.yaml`。MySQL 容器首次启动时会自动按顺序执行：

1. `sql/init.sql`
2. `sql/v2_alter.sql`
3. `sql/v3_alter.sql`

默认配置与服务启动参数保持一致：

| 配置 | 默认值 |
|---|---|
| MySQL 容器名 | `ny_auth_mysql` |
| 本机端口 | `3306` |
| root 密码 | `123456` |
| 数据库 | `ny_auth` |

启动 MySQL：

```bash
cp .env.example .env
docker compose up -d mysql
```

确认 MySQL 已就绪：

```bash
docker compose ps
docker compose exec mysql mysql -uroot -p123456 -e "SHOW DATABASES;"
```

如果需要查看初始化后的表：

```bash
docker compose exec mysql mysql -uroot -p123456 ny_auth -e "SHOW TABLES;"
```

如果你修改了 `sql/*.sql` 并希望重新初始化数据库，需要删除旧数据卷后再启动：

```bash
docker compose down -v
docker compose up -d mysql
```

> 注意：`docker compose down -v` 会删除本地 MySQL 数据卷，只适合开发和测试环境使用。

如果本机 `3306` 端口已经被占用，可以修改 `.env`：

```bash
MYSQL_PORT=3307
```

之后启动服务时同步改成 `--db_port=3307`。

#### 手动 MySQL 初始化方式

项目默认使用 MySQL。初始化脚本会创建 `ny_auth` 数据库、基础 RBAC 表、资源表、策略版本表和决策日志表，并写入一批测试数据。

> 注意：`sql/init.sql` 会先删除同名旧表，适合本地开发和测试环境使用。生产环境请先备份数据。

```bash
mysql -u root -p < sql/init.sql
```

启用 V2 管理端能力时，继续执行升级脚本：

```bash
mysql -u root -p < sql/v2_alter.sql
```

启用 V3 Agent / Sidecar 快照能力时，继续执行升级脚本：

```bash
mysql -u root -p < sql/v3_alter.sql
```

V2 脚本会创建：

- `ny_console_users`：管理端管理员账号表
- `ny_audit_logs`：管理员配置变更审计日志表

开发环境默认管理员账号：

```text
username: admin
password: admin123
```

> 请勿在生产环境使用默认密码。

### 3. 安装依赖

请确保本机已安装以下依赖，并且 CMake 能找到对应头文件和库文件：

```bash
# Ubuntu / Debian 示例，包名可能随发行版变化
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  pkg-config \
  protobuf-compiler \
  libprotobuf-dev \
  libssl-dev \
  zlib1g-dev \
  libleveldb-dev \
  libgflags-dev \
  default-libmysqlclient-dev
```

brpc 和 MySQL Connector/C++ 的安装方式请根据你的系统环境选择源码编译或包管理器安装。

### 4. 编译

```bash
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

编译成功后会生成：

```text
auth_server
```

如果你修改了 `proto/auth.proto`，可以重新生成 `auth.pb.cc` 和 `auth.pb.h`：

```bash
protoc -I=proto --cpp_out=src proto/auth.proto
```

### 5. 启动服务

如果使用上面的 Docker MySQL 默认配置，可以直接启动：

```bash
./auth_server
```

或者显式指定参数：

```bash
./auth_server \
  --port=8001 \
  --db_host=127.0.0.1 \
  --db_port=3306 \
  --db_user=root \
  --db_password=123456 \
  --db_name=ny_auth \
  --cache_ttl=60 \
  --admin_session_ttl=3600
```

启动参数说明：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `--port` | `8001` | brpc 服务监听端口 |
| `--db_host` | `127.0.0.1` | MySQL 地址 |
| `--db_port` | `3306` | MySQL 端口 |
| `--db_user` | `root` | MySQL 用户名 |
| `--db_password` | - | MySQL 密码 |
| `--db_name` | `ny_auth` | MySQL 数据库名 |
| `--cache_ttl` | `60` | 权限缓存 TTL，单位秒 |
| `--admin_session_ttl` | `3600` | 管理端会话有效期，单位秒 |

## 核心鉴权接口

`proto/auth.proto` 中定义了 `AuthService`：

```protobuf
service AuthService {
  rpc Check(CheckRequest) returns (CheckResponse);
}
```

### CheckRequest

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `app_code` | string | 是 | 接入应用编码，例如 `doc_center` |
| `user_id` | string | 是 | 业务系统内的用户 ID |
| `perm_key` | string | 是 | 权限标识，例如 `document:edit` |
| `resource_type` | string | 否 | 资源类型，例如 `document` |
| `resource_id` | string | 否 | 资源 ID，例如 `doc_001` |
| `request_id` | string | 否 | 调用方请求 ID，便于日志追踪 |

`resource_type` 与 `resource_id` 必须同时为空或同时提供。

### CheckResponse

| 字段 | 类型 | 说明 |
|---|---|---|
| `allowed` | bool | 是否允许访问 |
| `reason` | string | 判权结果说明 |
| `current_roles` | repeated string | 当前用户已有角色 |
| `suggest_roles` | repeated string | 拒绝时建议授予的角色 |
| `deny_code` | enum | 拒绝或通过原因枚举 |
| `trace` | DecisionTrace | 可解释判权信息 |

`DecisionTrace` 包含：

- `matched_roles`：命中的角色
- `matched_permissions`：命中的权限
- `owner_shortcut_used`：是否使用 owner 快捷规则
- `policy_version`：策略版本
- `decision_source`：决策来源，数据库或缓存
- `trace_text`：调试说明

## 调用示例

brpc 支持通过 HTTP/JSON 方式调用 protobuf service。服务启动后，可以使用下面的方式测试。

### 示例 1：owner 快捷规则放行

`u1001` 是 `doc_001` 的 owner，且 `document:edit` 开启了 owner 快捷规则。

```bash
curl -X POST 'http://127.0.0.1:8001/ny.auth.AuthService/Check' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_code": "doc_center",
    "user_id": "u1001",
    "perm_key": "document:edit",
    "resource_type": "document",
    "resource_id": "doc_001",
    "request_id": "req_owner_edit_001"
  }'
```

期望结果：

```json
{
  "allowed": true,
  "reason": "资源 owner 快捷规则允许访问"
}
```

### 示例 2：普通 RBAC 放行

`u1002` 拥有 `viewer` 角色，`viewer` 角色拥有 `document:read` 权限。

```bash
curl -X POST 'http://127.0.0.1:8001/ny.auth.AuthService/Check' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_code": "doc_center",
    "user_id": "u1002",
    "perm_key": "document:read",
    "resource_type": "document",
    "resource_id": "doc_001",
    "request_id": "req_viewer_read_001"
  }'
```

期望结果：

```json
{
  "allowed": true,
  "reason": "用户权限允许访问"
}
```

### 示例 3：权限不足被拒绝

`u1002` 是 `viewer`，没有 `document:delete` 权限，且删除权限不允许 owner 快捷放行。

```bash
curl -X POST 'http://127.0.0.1:8001/ny.auth.AuthService/Check' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_code": "doc_center",
    "user_id": "u1002",
    "perm_key": "document:delete",
    "resource_type": "document",
    "resource_id": "doc_002",
    "request_id": "req_viewer_delete_001"
  }'
```

期望结果：

```json
{
  "allowed": false,
  "reason": "用户没有该权限"
}
```

## 管理端接口（V2）

V2 管理端服务提供以下能力：

- `Login`：管理员登录
- `CreateRole`：创建角色
- `CreatePermission`：创建权限
- `BindPermissionToRole`：绑定权限到角色
- `GrantRoleToUser`：授予用户角色
- `SetResourceOwner`：设置资源 owner
- `PublishPolicy`：发布策略版本
- `SimulateCheck`：模拟鉴权
- `ListAuditLogs`：查询审计日志

示例：管理员登录

```bash
curl -X POST 'http://127.0.0.1:8001/ny.admin.AdminService/Login' \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

登录成功后会返回 `token`，后续管理端操作通过 `operator_token` 传入该 token。

## 数据库模型概览

基础表：

| 表名 | 说明 |
|---|---|
| `ny_apps` | 接入应用表 |
| `ny_policy_versions` | 应用策略版本表 |
| `ny_roles` | 角色表 |
| `ny_permissions` | 权限表 |
| `ny_role_permissions` | 角色-权限关系表 |
| `ny_user_roles` | 用户-角色关系表 |
| `ny_resources` | 资源与 owner 关系表 |
| `ny_decision_logs` | 每次鉴权的决策日志 |

V2 管理端表：

| 表名 | 说明 |
|---|---|
| `ny_console_users` | 管理端用户表 |
| `ny_audit_logs` | 管理员配置变更审计日志表 |

## 决策流程

一次 `Check` 请求大致经过以下流程：

1. 校验 `app_code`、`user_id`、`perm_key` 等必要参数。
2. 查询应用是否存在、是否启用，并读取当前策略版本。
3. 校验目标权限是否存在。
4. 如果请求携带资源信息，检查资源是否存在且启用。
5. 尝试 owner 快捷规则。
6. owner 未放行时，从本地缓存或数据库加载用户权限集合。
7. 使用 RBAC 判断用户是否拥有目标权限。
8. 生成可解释 trace，并写入 `ny_decision_logs`。

## 本地缓存策略

权限缓存 key 由以下字段组成：

```text
app_code:user_id:policy_version
```

当策略发布后，`policy_version` 递增，新的请求会自然使用新的缓存 key，避免直接清空所有缓存。

## 常见问题

### 1. CMake 报错：`mysqlcppconn not found`

请确认已安装 MySQL Connector/C++，并且 `mysql_driver.h` 与 `mysqlcppconn` 库能被 CMake 找到。

### 2. CMake 报错：找不到 brpc

请确认 brpc 已正确安装，并且 `pkg-config --libs brpc` 能返回有效结果。

### 3. 修改 proto 后如何重新生成代码？

```bash
protoc -I=proto --cpp_out=src proto/auth.proto
```

### 4. 链接阶段出现 AdminService 相关 undefined reference

如果启用了 `server_main.cpp` 中的管理端服务，请确认 `CMakeLists.txt` 已经把以下文件加入 `auth_server` 目标：

```text
src/admin.pb.cc
src/admin_dao.cpp
src/admin_manager.cpp
src/admin_service_impl.cpp
src/simulation_engine.cpp
```

同时确认对应头文件位于 include path 中。
