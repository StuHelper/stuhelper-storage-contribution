# StuHelper Storage Contribution

独立存储贡献库，管理同意、容量、期限、暂停、退出和迁移观测。通过 storage 公共接口协作，不保存供应商凭据，不读写业务或账务数据。

运行要求为 Go 1.27.3、Node.js 24.22.1、pnpm 10.33.4 和隔离 PostgreSQL 18。使用 `make setup` 安装锁定工具，`bash scripts/check-with-postgres.sh` 启动临时数据库并执行全部检查。

OpenAPI 位于 contracts，`make generate` 生成 SDK。独立应用装配提供运行身份、条款、容量及期限配置、当前授权检查，并持续执行有界 `Sweep` 与 `RunOne`。代码本身不会登录供应商或启动后台进程。

行为及剩余范围见 [贡献规格](docs/spec/contribution.md)。许可为 AGPL-3.0-only。
