# Nacos Client API 手册

## 概述

Nacos Client 是一个 Docker Compose 服务管理 Web 服务器，提供服务管理、升级、健康检查、系统监控等功能。

**服务版本**: 1.0.0
**认证方式**: 通过 `X-Auth-Token` 请求头或请求参数传递 Token

---

## 版本号说明

- 版本由 `build.sh` 在打包时动态生成，并写入 `nacos/version.json`。
- API 返回以下版本字段：
  - `nacos_agent_version`：日期构建号（如 `20260101.010101`）
  - `nacos_agent_version_human`：人类可读版本（如 `v2026.01.01 (build 010101)`）
  - `nacos_agent_version_semver`：语义化展示版本（如 `2026.1.1+010101`）

---

## API 汇总

### 1. 静态文件管理 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| GET | `/api/static/info` | 获取静态文件信息 | 需要 |
| POST | `/api/static/upload` | 上传静态文件 | 需要 |
| DELETE | `/api/static/delete` | 删除静态文件 | 需要 |

### 2. 鉴权 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| POST | `/api/auth/validate` | 验证Token有效性 | 不需要 |
| GET | `/api/auth/info` | 获取认证信息 | 不需要 |

### 3. 系统信息 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| GET | `/api/system/info` | 获取系统完整信息 | 需要 |
| GET | `/api/system/metrics` | 获取系统性能指标(轻量版) | 需要 |
| GET | `/api/system/processes` | 获取系统进程信息 | 需要 |
| GET | `/api/system/docker/stats` | 获取Docker容器统计信息 | 需要 |
| GET | `/api/system/docker/images` | 获取Docker镜像信息 | 需要 |

### 4. 健康检查 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| GET | `/api/health` | 健康检查 | 不需要 |

### 5. 服务管理 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| GET | `/api/services` | 列出所有服务 | 需要 |
| GET | `/api/services/<service_name>` | 获取服务详情 | 需要 |
| POST | `/api/services/yaml` | 从YAML创建服务 | 需要 |
| POST | `/api/services/zip` | 从压缩包创建服务 | 需要 |
| POST | `/api/services/<service_name>/start` | 启动服务 | 需要 |
| POST | `/api/services/<service_name>/stop` | 停止服务 | 需要 |
| POST | `/api/services/<service_name>/restart` | 重启服务 | 需要 |
| DELETE | `/api/services/<service_name>` | 删除服务 | 需要 |
| PUT | `/api/services/<service_name>/enable` | 启用服务 | 需要 |
| PUT | `/api/services/<service_name>/disable` | 禁用服务 | 需要 |
| GET | `/api/services/<service_name>/logs` | 获取服务日志 | 需要 |
| POST | `/api/services/<service_name>/exec` | 执行容器命令 | 需要 |
| GET | `/api/services/<service_name>/files` | 获取服务文件夹结构 | 需要 |
| GET | `/api/services/<service_name>/files/download` | 下载服务文件 | 需要 |
| PUT | `/api/services/<service_name>/files/update` | 更新服务文件 | 需要 |

### 6. 校验 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| GET | `/api/validate/data` | 校验数据一致性 | 需要 |
| GET | `/api/validate/services` | 校验服务状态 | 需要 |
| POST | `/api/validate/fix` | 修复校验问题 | 需要 |

### 7. 升级 API

| 方法 | 路径 | 功能 | 认证 |
|------|------|------|------|
| POST | `/api/upgrade` | 升级服务器 | 需要 |

---

## API 详细说明

### 1. 静态文件管理 API

#### 1.1 获取静态文件信息

**请求**
```
GET /api/static/info
```

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 说明 |
|--------|------|------|------|------|
| path | string | query | 否 | 文件路径 |

**响应示例**
```json
{
  "exists": true,
  "path": "/path/to/file",
  "size": 1024,
  "modified": "2024-01-01T00:00:00"
}
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 1.2 上传静态文件

**请求**
```
POST /api/static/upload
Content-Type: multipart/form-data
```

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 说明 |
|--------|------|------|------|------|
| file | file | form | 是 | 上传的文件 |
| path | string | form | 否 | 目标路径(相对于静态文件目录) |

**响应示例**
```json
{
  "message": "文件上传成功",
  "path": "relative/path/to/file.txt",
  "size": 1024
}
```

**错误响应**
- 400: 未找到文件/文件名为空
- 401: 认证失败
- 500: 服务器内部错误

---

#### 1.3 删除静态文件

**请求**
```
DELETE /api/static/delete
Content-Type: application/json
```

**请求体**
```json
{
  "path": "relative/path/to/delete"
}
```

**请求参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| path | string | 是 | 要删除的文件/目录路径 |

**响应示例**
```json
{
  "message": "文件删除成功",
  "path": "relative/path/to/delete"
}
```

**错误响应**
- 400: 请求体必须为JSON/文件路径为空/不允许删除目录外文件
- 401: 认证失败
- 404: 文件不存在
- 500: 服务器内部错误

---

### 2. 鉴权 API

#### 2.1 验证Token有效性

**请求**
```
POST /api/auth/validate
```

**请求参数**

Token 可通过以下方式传递:
- 请求头: `X-Auth-Token`
- JSON 请求体: `{"token": "your_token"}`
- 表单数据: `token=your_token`

**响应示例**
```json
{
  "authenticated": true,
  "message": "Token验证成功",
  "timestamp": "2024-01-01T00:00:00",
  "token_provided": "your_token",
  "token_length": 16,
  "token_match": true,
  "client_ip": "127.0.0.1",
  "user_agent": "Mozilla/5.0...",
  "request_method": "POST",
  "request_path": "/api/auth/validate",
  "nacos_agent_version": "20260101.0101",
  "nacos_agent_version_human": "v2026.01.01 (build 0101)",
  "nacos_agent_version_semver": "2026.1.1+0101"
}
```

**错误响应**
- 401: Token验证失败

---

#### 2.2 获取认证信息

**请求**
```
GET /api/auth/info
```

**响应示例**
```json
{
  "timestamp": "2024-01-01T00:00:00",
  "client_ip": "127.0.0.1",
  "user_agent": "Mozilla/5.0...",
  "request_method": "GET",
  "request_path": "/api/auth/info",
  "has_token_provided": true,
  "token_provided_length": 16,
  "config_token_length": 32,
  "config_token_prefix": "abc...",
  "auth_required": true,
  "auth_method": "X-Auth-Token header or token parameter",
  "nacos_agent_version": "20260101.0101",
  "nacos_agent_version_human": "v2026.01.01 (build 0101)",
  "nacos_agent_version_semver": "2026.1.1+0101",
  "message": "此API不需要认证，仅用于获取认证信息"
}
```

---

### 3. 系统信息 API

#### 3.1 获取系统完整信息

**请求**
```
GET /api/system/info
```

**响应示例**
```json
{
  "timestamp": "2024-01-01T00:00:00",
  "nacos_agent_version": "20260101.0101",
  "nacos_agent_version_human": "v2026.01.01 (build 0101)",
  "nacos_agent_version_semver": "2026.1.1+0101",
  "hostname": "server-01",
  "os_name": "Linux",
  "os_version": "Ubuntu 22.04.3 LTS",
  "os_release": "22.04",
  "kernel_version": "5.15.0-91-generic",
  "architecture": "x86_64",
  "boot_time": "2024-01-01T00:00:00",
  "uptime": 86400,
  "cpu": {
    "physical_cores": 8,
    "logical_cores": 16,
    "usage_percent": 25.5,
    "model": "Intel(R) Core(TM) i9-9900K",
    "architecture": "x86_64",
    "frequency_current": 3600.0,
    "frequency_max": 5000.0,
    "load_average_1min": 1.5,
    "load_average_5min": 2.0,
    "load_average_15min": 1.8
  },
  "memory": {
    "total": 34359738368,
    "available": 17179869184,
    "used": 17179869184,
    "free": 0,
    "usage_percent": 50.0,
    "swap_total": 8589934592,
    "swap_used": 0,
    "swap_free": 8589934592,
    "swap_usage_percent": 0.0
  },
  "disks": [...],
  "network_interfaces": [...],
  "docker": {
    "version": "24.0.5",
    "api_version": "1.43",
    "containers_total": 10,
    "containers_running": 8,
    "containers_stopped": 2,
    "containers_paused": 0,
    "images_total": 15,
    "images_size": 5368709120,
    "volumes_total": 5,
    "networks_total": 3,
    "is_docker_available": true,
    "docker_root_dir": "/var/lib/docker"
  },
  "processes_top": [...],
  "formatted": {
    "nacos_agent_version": "20260101.0101",
    "nacos_agent_version_human": "v2026.01.01 (build 0101)",
    "nacos_agent_version_semver": "2026.1.1+0101",
    "uptime": "1 day, 0:00:00",
    "memory": {
      "total": "32.00 GB",
      "available": "16.00 GB",
      "used": "16.00 GB",
      "free": "0 B"
    },
    "disks": [...],
    "docker": {
      "images_size": "5.00 GB",
      "containers": "8/10 运行中"
    }
  }
}
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 3.2 获取系统性能指标(轻量版)

**请求**
```
GET /api/system/metrics
```

**响应示例**
```json
{
  "timestamp": "2024-01-01T00:00:00",
  "cpu": {
    "percent": 25.5,
    "cores": 16,
    "load_average": [1.5, 2.0, 1.8]
  },
  "memory": {
    "total": 34359738368,
    "available": 17179869184,
    "used": 17179869184,
    "percent": 50.0,
    "swap_total": 8589934592,
    "swap_used": 0,
    "swap_percent": 0.0
  },
  "disk": [...],
  "network": {
    "bytes_sent": 1073741824,
    "bytes_recv": 2147483648,
    "packets_sent": 1000000,
    "packets_recv": 2000000
  },
  "docker": {
    "containers_total": 10,
    "containers": [...]
  },
  "formatted": {
    "cpu_percent": "25.5%",
    "memory_percent": "50.0%",
    "memory_used": "16.00 GB",
    "memory_total": "32.00 GB",
    "network_sent": "1.00 GB",
    "network_recv": "2.00 GB"
  }
}
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 3.3 获取系统进程信息

**请求**
```
GET /api/system/processes
```

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 默认值 | 说明 |
|--------|------|------|------|--------|------|
| sort | string | query | 否 | cpu_percent | 排序字段(cpu_percent/memory_percent/memory_rss) |
| order | string | query | 否 | desc | 排序方向(asc/desc) |
| limit | int | query | 否 | 50 | 每页数量(最大100) |
| page | int | query | 否 | 1 | 页码 |

**响应示例**
```json
{
  "total": 200,
  "page": 1,
  "per_page": 50,
  "processes": [
    {
      "pid": 1234,
      "name": "python3",
      "username": "root",
      "status": "running",
      "cpu_percent": 15.5,
      "memory_percent": 5.2,
      "memory_rss": 1782579200,
      "create_time": 1704067200.0,
      "cmdline": "/usr/bin/python3 /app/main.py"
    }
  ]
}
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 3.4 获取Docker容器统计信息

**请求**
```
GET /api/system/docker/stats
```

**响应示例**
```json
[
  {
    "id": "abc123",
    "name": "web-server",
    "status": "running",
    "image": "nginx:latest",
    "cpu_percent": 2.5,
    "memory_usage": 104857600,
    "memory_limit": 2147483648,
    "memory_percent": 4.88,
    "network_rx": 1073741824,
    "network_tx": 536870912,
    "pids": 10,
    "formatted": {
      "memory_usage": "100.00 MB",
      "memory_limit": "2.00 GB",
      "network_rx": "1.00 GB",
      "network_tx": "512.00 MB"
    }
  }
]
```

**错误响应**
- 401: 认证失败
- 503: Docker客户端不可用
- 500: 服务器内部错误

---

#### 3.5 获取Docker镜像信息

**请求**
```
GET /api/system/docker/images
```

**响应示例**
```json
[
  {
    "id": "sha256:abc123",
    "tags": ["nginx:latest", "nginx:1.25"],
    "created": "2024-01-01T00:00:00Z",
    "size": 142606336,
    "virtual_size": 142606336,
    "labels": {},
    "formatted": {
      "size": "135.92 MB",
      "virtual_size": "135.92 MB"
    }
  }
]
```

**错误响应**
- 401: 认证失败
- 503: Docker客户端不可用
- 500: 服务器内部错误

---

### 4. 健康检查 API

#### 4.1 健康检查

**请求**
```
GET /api/health
```

**响应示例**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00",
  "version": "2026.1.1+0101",
  "nacos_agent_version": "20260101.0101",
  "nacos_agent_version_human": "v2026.01.01 (build 0101)"
}
```

---

### 5. 服务管理 API

#### 5.1 列出所有服务

**请求**
```
GET /api/services
```

**响应示例**
```json
[
  {
    "id": 1,
    "name": "web-server",
    "path": "/opt/services/web-server",
    "enabled": 1,
    "status": "running",
    "created_at": "2024-01-01T00:00:00",
    "updated_at": "2024-01-01T00:00:00",
    "real_status": {
      "status": "running",
      "containers": [...]
    }
  }
]
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.2 获取服务详情

**请求**
```
GET /api/services/<service_name>
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "id": 1,
  "name": "web-server",
  "path": "/opt/services/web-server",
  "enabled": 1,
  "status": "running",
  "created_at": "2024-01-01T00:00:00",
  "updated_at": "2024-01-01T00:00:00",
  "real_status": {
    "status": "running",
    "containers": [...]
  },
  "yaml_content": "version: '3'\nservices:\n  web:\n    image: nginx"
}
```

**错误响应**
- 401: 认证失败
- 404: 服务不存在
- 500: 服务器内部错误

---

#### 5.3 从YAML创建服务

**请求**
```
POST /api/services/yaml
Content-Type: application/json
```

**请求体**
```json
{
  "name": "web-server",
  "yaml": "version: '3'\nservices:\n  web:\n    image: nginx"
}
```

**请求参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| name | string | 是 | 服务名称 |
| yaml | string | 是 | docker-compose YAML内容 |

**响应示例**
```json
{
  "message": "服务创建成功"
}
```

**错误响应**
- 400: 服务名称或YAML内容为空
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.4 从压缩包创建服务

**请求**
```
POST /api/services/zip
Content-Type: multipart/form-data
```

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 说明 |
|--------|------|------|------|------|
| file | file | form | 是 | 压缩包文件(支持.zip/.tar.gz等) |
| name | string | form | 是 | 服务名称 |

**响应示例**
```json
{
  "message": "服务创建成功",
  "service": "web-server",
  "file_type": ".zip"
}
```

**错误响应**
- 400: 未找到文件/服务名称为空/文件名为空
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.5 启动服务

**请求**
```
POST /api/services/<service_name>/start
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "message": "服务启动成功"
}
```

**错误响应**
- 400: 启动失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.6 停止服务

**请求**
```
POST /api/services/<service_name>/stop
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "message": "服务停止成功"
}
```

**错误响应**
- 400: 停止失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.7 重启服务

**请求**
```
POST /api/services/<service_name>/restart
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "message": "服务重启成功"
}
```

**错误响应**
- 400: 重启失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.8 删除服务

**请求**
```
DELETE /api/services/<service_name>
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 默认值 | 说明 |
|--------|------|------|------|--------|------|
| force | string | query | 否 | false | 是否强制删除(true/false) |

**响应示例**
```json
{
  "message": "服务删除成功"
}
```

**错误响应**
- 400: 删除失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.9 启用服务

**请求**
```
PUT /api/services/<service_name>/enable
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "message": "服务启用成功"
}
```

**错误响应**
- 400: 启用失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.10 禁用服务

**请求**
```
PUT /api/services/<service_name>/disable
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "message": "服务禁用成功"
}
```

**错误响应**
- 400: 禁用失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.11 获取服务日志

**请求**
```
GET /api/services/<service_name>/logs
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 默认值 | 说明 |
|--------|------|------|------|--------|------|
| tail | int | query | 否 | 100 | 日志行数 |

**响应示例**
```json
{
  "logs": "service logs here..."
}
```

**错误响应**
- 400: 获取失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.12 在容器中执行命令

**请求**
```
POST /api/services/<service_name>/exec
Content-Type: application/json
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**请求体**
```json
{
  "container": "web",
  "command": "ls -la",
  "user": "root"
}
```

**请求参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| container | string | 是 | 容器名称 |
| command | string | 是 | 要执行的命令 |
| user | string | 否 | 执行用户 |

**响应示例**
```json
{
  "output": "command output here..."
}
```

**错误响应**
- 400: 容器名称或命令为空/执行失败
- 401: 认证失败
- 500: 服务器内部错误

---

#### 5.13 获取服务文件夹结构

**请求**
```
GET /api/services/<service_name>/files
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**响应示例**
```json
{
  "name": "web-server",
  "path": "/opt/services/web-server",
  "type": "directory",
  "children": [
    {
      "name": "docker-compose.yaml",
      "path": "/opt/services/web-server/docker-compose.yaml",
      "type": "file",
      "size": 256
    }
  ]
}
```

**错误响应**
- 401: 认证失败
- 404: 服务不存在
- 500: 服务器内部错误

---

#### 5.14 下载服务文件

**请求**
```
GET /api/services/<service_name>/files/download
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 说明 |
|--------|------|------|------|------|
| path | string | query | 是 | 文件路径(相对于服务目录) |

**响应**

返回文件下载流 (`application/octet-stream`)

**错误响应**
- 400: 文件路径为空
- 401: 认证失败
- 404: 文件不存在
- 500: 服务器内部错误

---

#### 5.15 更新服务文件

**请求**
```
PUT /api/services/<service_name>/files/update
Content-Type: multipart/form-data
```

**路径参数**

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| service_name | string | 是 | 服务名称 |

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 说明 |
|--------|------|------|------|------|
| path | string | form | 是 | 文件路径(相对于服务目录) |
| file | file | form | 是 | 新文件内容 |

**响应示例**
```json
{
  "message": "文件更新成功",
  "path": "config/app.conf"
}
```

**错误响应**
- 400: 文件路径或内容为空
- 401: 认证失败
- 404: 文件不存在
- 500: 服务器内部错误

---

### 6. 校验 API

#### 6.1 校验数据一致性

校验服务的文件状态与数据库记录是否一致。

**请求**
```
GET /api/validate/data
```

**响应示例**
```json
{
  "total": 10,
  "consistent": [
    {
      "service": "web-server",
      "path": "/opt/services/web-server",
      "status": "ok"
    }
  ],
  "inconsistent": [
    {
      "service": "api-server",
      "issue": "文件夹不存在",
      "db_path": "/opt/services/api-server",
      "actual_path": "不存在"
    }
  ],
  "orphaned_folders": [
    {
      "folder": "old-service",
      "path": "/opt/services/old-service",
      "issue": "存在服务文件夹但数据库中没有记录"
    }
  ],
  "summary": {
    "consistent_count": 8,
    "inconsistent_count": 1,
    "orphaned_count": 1,
    "consistency_percentage": 80.0
  }
}
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 6.2 校验服务状态

校验服务状态是否符合配置(使能/非使能)。

**请求**
```
GET /api/validate/services
```

**响应示例**
```json
{
  "total": 10,
  "valid": [...],
  "invalid": [
    {
      "service": "api-server",
      "enabled": true,
      "db_status": "running",
      "real_status": "stopped",
      "containers_count": 1,
      "containers": [...],
      "healthy_containers": 0,
      "unhealthy_containers": 1,
      "all_healthy": false,
      "valid": false,
      "validation_errors": ["服务已启用但状态为stopped"]
    }
  ],
  "health_checks": {
    "enabled_healthy": ["web-server"],
    "enabled_unhealthy": [...],
    "disabled_running": [...],
    "disabled_stopped": ["backup-service"]
  },
  "summary": {
    "valid_count": 8,
    "invalid_count": 2,
    "enabled_healthy_count": 5,
    "enabled_unhealthy_count": 1,
    "disabled_stopped_count": 3,
    "disabled_running_count": 1,
    "validation_percentage": 80.0
  },
  "suggested_fixes": [
    {
      "service": "api-server",
      "action": "restart",
      "reason": "服务已启用但1个容器不健康",
      "command": "POST /api/services/api-server/restart"
    }
  ]
}
```

**错误响应**
- 401: 认证失败
- 500: 服务器内部错误

---

#### 6.3 修复校验问题

**请求**
```
POST /api/validate/fix
Content-Type: application/json
```

**请求体**
```json
{
  "type": "all",
  "auto_execute": true
}
```

**请求参数**

| 参数名 | 类型 | 必填 | 默认值 | 说明 |
|--------|------|------|--------|------|
| type | string | 否 | all | 修复类型(all/orphaned/inconsistent/state) |
| auto_execute | boolean | 否 | false | 是否自动执行修复 |

**响应示例**
```json
{
  "total_fixes": 3,
  "executed_fixes": 3,
  "failed_fixes": [],
  "fix_operations": [
    {
      "type": "orphaned_folder",
      "folder": "old-service",
      "action": "added_to_database",
      "service_name": "old-service",
      "status": "success"
    },
    {
      "type": "state_mismatch",
      "service": "api-server",
      "action": "start",
      "status": "success",
      "message": "服务启动成功"
    }
  ],
  "summary": {
    "fix_success_rate": 100.0
  }
}
```

**错误响应**
- 400: 请求体必须为JSON
- 401: 认证失败
- 500: 服务器内部错误

---

### 7. 升级 API

#### 7.1 升级服务器

**请求**
```
POST /api/upgrade
Content-Type: multipart/form-data
```

**请求参数**

| 参数名 | 类型 | 位置 | 必填 | 说明 |
|--------|------|------|------|------|
| file | file | form | 是 | Python文件(.py) |

**响应示例**
```json
{
  "message": "升级成功，服务器将在2秒后重启",
  "backup_file": "/opt/nacos_client/nacos_client_main.backup.20240101000000.py",
  "file_hash": "abc123def456..."
}
```

**错误响应**
- 400: 未找到文件/只能上传Python文件
- 401: 认证失败
- 500: 服务器内部错误

---

## 通用错误响应

### 认证失败 (401)
```json
{
  "error": "认证失败"
}
```

### 服务器内部错误 (500)
```json
{
  "error": "错误详情..."
}
```

---

## 认证说明

大部分 API 需要通过 Token 进行认证。Token 可通过以下方式传递：

1. **请求头方式** (推荐)
   ```
   X-Auth-Token: your_token_here
   ```

2. **JSON 请求体方式**
   ```json
   {
     "token": "your_token_here"
   }
   ```

3. **表单数据方式**
   ```
   token=your_token_here
   ```

---

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0.0 | 2024-01-01 | 初始版本 |
