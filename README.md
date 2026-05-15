# ny_auth

`ny_auth` 是一个基于 C++17、brpc、Protobuf 和 MySQL 的权限鉴权服务。它提供中心化鉴权、RBAC 授权、资源 owner 快捷规则、管理端策略维护、策略快照发布，以及 Agent / Sidecar 本地快照判权能力。

项目内置了一组 `doc_center` 测试数据，适合用来验证从“创建策略”到“在线鉴权”和“本地快照判权”的完整链路。

## 功能

- 中心化鉴权：通过 `AuthService.Check` 判断用户是否拥有某个权限。
- RBAC 模型：支持用户、角色、权限、角色权限绑定、用户角色绑定。
- owner 快捷规则：资源 owner 可在指定权限上直接放行。
- 策略版本：发布策略后递增 `policy_version`，缓存 key 自动切换到新版本。
- 决策解释：返回命中的角色、权限、判权来源、拒绝码和 trace 文本。
- 管理端接口：支持登录、创建角色、创建权限、绑定权限、授权用户、设置资源 owner、发布策略、模拟鉴权和审计日志查询。
- 策略快照：发布策略时生成只读快照，供 Agent / Sidecar 拉取和激活。
- 本地判权：Agent / Sidecar 可基于已激活快照执行本地权限判断。

## 技术栈

- C++17
- CMake 3.10+
- brpc
- Protobuf
- MySQL 8.0 / MySQL Connector C++
- gflags
- pthread、OpenSSL、zlib、LevelDB 等 brpc 相关依赖

## 目录结构

```text
ny_auth/
├── CMakeLists.txt
├── compose.yaml
├── include/                 # 业务头文件
├── proto/                   # RPC 协议定义
│   ├── auth.proto
│   ├── admin.proto
│   └── agent.proto
├── sql/
│   └── init.sql             # 完整初始化脚本和测试数据
├── src/                     # 业务实现和生成的 protobuf C++ 文件
└── tests/
    └── local_cache_test.cpp
```

## 快速开始

### 1. 准备 MySQL

推荐使用 Docker Compose 启动 MySQL：

```bash
docker compose up -d mysql
```

当前 `compose.yaml` 默认把容器内 `3306` 映射到本机 `3307`。如果你想使用其他本机端口：

```bash
MYSQL_PORT=3308 docker compose up -d mysql
```

确认数据库已启动：

```bash
docker compose ps
docker compose exec mysql mysql -uroot -p123456 -e "SHOW DATABASES;"
docker compose exec mysql mysql -uroot -p123456 ny_auth -e "SHOW TABLES;"
```

首次启动时，MySQL 会自动执行 `sql/init.sql`。该脚本会创建 `ny_auth` 数据库、所有业务表和一组测试数据。

如果改过 SQL 并需要重新初始化本地数据库：

```bash
docker compose down -v
docker compose up -d mysql
```

注意：`docker compose down -v` 会删除本地 MySQL 数据卷，只适合开发和测试环境。

### 2. 安装依赖

Ubuntu / Debian 示例：

```bash
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

还需要安装 brpc 和 MySQL Connector/C++，并确保 `pkg-config --libs brpc`、`mysql_driver.h`、`libmysqlcppconn` 能被 CMake 找到。

### 3. 编译

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j$(nproc)
```

编译产物：

```text
build/auth_server
build/local_cache_test
```

### 4. 运行测试

```bash
cd build
ctest --output-on-failure
```

也可以直接运行缓存测试：

```bash
./local_cache_test
```

### 5. 启动服务

如果使用默认 Docker Compose 配置，本机 MySQL 端口是 `3307`：

```bash
./build/auth_server \
  --port=8001 \
  --db_host=127.0.0.1 \
  --db_port=3307 \
  --db_user=root \
  --db_password=123456 \
  --db_name=ny_auth \
  --cache_ttl=60 \
  --admin_session_ttl=3600
```

如果你的 MySQL 就在本机 `3306`，可以省略 `--db_port` 或显式传 `--db_port=3306`。

常用启动参数：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `--port` | `8001` | brpc 服务监听端口 |
| `--db_host` | `127.0.0.1` | MySQL 地址 |
| `--db_port` | `3306` | MySQL 端口 |
| `--db_user` | `root` | MySQL 用户名 |
| `--db_password` | `123456` | MySQL 密码 |
| `--db_name` | `ny_auth` | MySQL 数据库 |
| `--cache_ttl` | `60` | 权限缓存 TTL，单位秒 |
| `--admin_session_ttl` | `3600` | 管理端登录态 TTL，单位秒 |
| `--agent_bootstrap_app_code` | 空 | 启动时自动加载指定 app 的最新快照 |

## 初始化数据

`sql/init.sql` 默认写入一个测试应用：

| 项 | 值 |
|---|---|
| app_code | `doc_center` |
| app_secret | `secret_doc_center_123` |
| 管理员账号 | `admin` |
| 管理员密码 | `admin123` |

测试用户和角色：

| 用户 | 角色 | 说明 |
|---|---|---|
| `u9000` | `admin` | 管理员角色 |
| `u1001` | `editor` | 可读、编辑、发布文档 |
| `u1002` | `viewer` | 只能读取文档 |
| `u3001` | 无 | 用于验证 owner 快捷规则 |

测试资源：

| resource_id | owner |
|---|---|
| `doc_001` | `u1001` |
| `doc_002` | `u1002` |
| `doc_003` | `u3001` |
| `doc_004` | `u1002` |

## 核心接口

brpc 开启 HTTP / JSON 访问后，可以按下面的形式调用：

```text
http://127.0.0.1:8001/<package.Service>/<Method>
```

### 中心化鉴权

接口：

```protobuf
service AuthService {
  rpc Check(CheckRequest) returns (CheckResponse);
}
```

owner 快捷规则放行：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.auth.AuthService/Check' \
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

RBAC 放行：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.auth.AuthService/Check' \
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

权限不足：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.auth.AuthService/Check' \
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

### 管理端登录

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.admin.AdminService/Login' \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

响应里的 `session.token` 是后续管理接口的 `operator_token`。

### 发布策略并生成快照

先把登录响应里的 token 放进环境变量：

```bash
TOKEN='把 Login 返回的 session.token 放这里'
```

发布策略：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.admin.AdminService/PublishPolicy' \
  -H 'Content-Type: application/json' \
  -d "{
    \"operator_token\": \"${TOKEN}\",
    \"app_code\": \"doc_center\",
    \"publish_note\": \"manual test publish\"
  }"
```

成功后会递增 `ny_policy_versions.current_version`，并写入 `ny_policy_snapshots` 和 `ny_snapshot_publish_logs`。

### Agent 拉取和激活快照

拉取最新快照：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.agent.AgentService/PullLatestSnapshot' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_code": "doc_center"
  }'
```

激活最新快照：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.agent.AgentService/ActivateLatestSnapshot' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_code": "doc_center"
  }'
```

基于本地快照判权：

```bash
curl -s -X POST 'http://127.0.0.1:8001/ny.agent.AgentService/LocalCheck' \
  -H 'Content-Type: application/json' \
  -d '{
    "app_code": "doc_center",
    "user_id": "u1001",
    "perm_key": "document:edit",
    "resource_type": "document",
    "resource_id": "doc_001",
    "request_id": "req_local_owner_edit_001"
  }'
```

## 数据库表

基础策略表：

| 表名 | 说明 |
|---|---|
| `ny_apps` | 接入应用 |
| `ny_policy_versions` | 应用当前策略版本 |
| `ny_roles` | 角色 |
| `ny_permissions` | 权限 |
| `ny_role_permissions` | 角色-权限绑定 |
| `ny_user_roles` | 用户-角色绑定 |
| `ny_resources` | 资源 owner 数据 |
| `ny_decision_logs` | 每次鉴权的决策日志 |

管理端和快照表：

| 表名 | 说明 |
|---|---|
| `ny_console_users` | 管理员账号 |
| `ny_audit_logs` | 管理操作审计日志 |
| `ny_policy_snapshots` | 策略快照 |
| `ny_snapshot_publish_logs` | 快照发布日志 |

## 判权流程

1. 校验 `app_code`、`user_id`、`perm_key`、资源参数。
2. 查询应用是否存在、是否启用，并读取当前策略版本。
3. 校验权限是否存在、是否启用。
4. 如果传了资源，校验资源是否存在、是否启用。
5. 尝试 owner 快捷规则。
6. owner 未放行时，从本地缓存或数据库加载用户权限集合。
7. 使用 RBAC 判断用户是否拥有目标权限。
8. 返回可解释 trace，并写入 `ny_decision_logs`。

缓存 key 格式：

```text
app_code:user_id:policy_version
```

策略发布后版本递增，新请求自然使用新缓存 key，不需要全量清空缓存。

## 重新生成 Protobuf 代码

修改 `proto/*.proto` 后执行：

```bash
protoc -I=proto --cpp_out=src proto/auth.proto
protoc -I=proto --cpp_out=src proto/admin.proto
protoc -I=proto --cpp_out=src proto/agent.proto
```

然后重新构建：

```bash
cmake --build build -j$(nproc)
```

## 常见问题

### 服务启动时报数据库连接失败

如果用 Docker Compose 默认配置，请确认服务启动参数包含：

```bash
--db_port=3307
```

也可以改用：

```bash
MYSQL_PORT=3306 docker compose up -d mysql
```

### `mysqlcppconn not found`

请确认已安装 MySQL Connector/C++，并且 CMake 能找到 `mysql_driver.h` 和 `libmysqlcppconn`。

### `pkg-config` 找不到 brpc

请确认 brpc 已正确安装，并且下面命令有输出：

```bash
pkg-config --cflags --libs brpc
```

### 登录密码说明

当前开发环境的默认管理员密码以明文形式初始化为 `admin123`，代码也采用简单字符串比较。生产环境应替换为安全的密码哈希方案，并移除默认账号或强制修改默认密码。

## 开发检查清单

提交前建议执行：

```bash
docker compose config --quiet
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```
