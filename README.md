# StuHelper Storage Contribution

独立存储贡献库，管理同意、容量、期限、暂停、退出和迁移观测。通过 storage 公共接口协作，不保存供应商凭据，不读写业务或账务数据。

运行要求为 Go 1.27.3、Node.js 24.22.1、pnpm 10.33.4 和隔离 PostgreSQL 18。使用 `make setup` 安装锁定工具，`bash scripts/check-with-postgres.sh` 启动临时数据库并执行全部检查。

OpenAPI 位于 contracts，`make generate` 生成 SDK。独立应用装配提供运行身份、条款、容量及期限配置、当前授权检查，并持续执行有界 `Sweep` 与 `RunOne`。代码本身不会登录供应商或启动后台进程。

宿主按 `Sweep` 返回的非空游标续扫，可同时清理过期同意与幂等回执。`RunOne` 在存储超时后记录退避；调用方取消时由租约到期恢复。

管理列表支持宿主通过 `OperationReadAuthorizer` 批量检查本页对象的读取权限。旧授权器仍可逐对象检查，两种方式均在贡献库事务外调用。

行为及剩余范围见 [贡献规格](docs/spec/contribution.md)。许可为 AGPL-3.0-only。
