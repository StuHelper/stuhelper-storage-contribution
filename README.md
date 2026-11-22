---
type: index
status: Accepted
updated: 2026-11-21
---

# StuHelper Storage Contribution

存储贡献库负责同意、申报条件、暂停、续期、退出及迁移观测。凭据托管、云盘容量采集和副本账本由 storage 负责。贡献同意独立于托管同意。

`module.json` 声明 storage 为必需依赖。账务模块 billing 是可选依赖，关闭账务时仍可管理贡献并读取统计。宿主负责注入授权、条款和策略，并调度 `Sweep` 与 `RunOne`，也可直接启用本库提供的 Worker。

`contracts/contribution.openapi.json` 定义 HTTP 接口，`make generate` 更新 SDK。本人候选、列表与详情返回私有云盘额度。公开统计汇总贡献申报量及账本可用量。完整规则见[贡献规格](docs/spec/contribution.md)。

## 开发与验证

使用工作区声明的工具链。执行 `make setup` 安装锁定工具，再运行 `bash scripts/check-with-postgres.sh` 启动临时 PostgreSQL 并执行 CI 使用的检查。已有专用测试服务器时，设置 `STUHELPER_CONTRIBUTION_TEST_DSN` 后运行 `make check`。

`module.json` 的 `scenario_tests` 将规格场景映射到实际测试函数。检查覆盖生成一致性、浏览器 SDK、权限、并发与独立数据库身份。宿主接入及真实账号验收见[存储实施状态](https://github.com/StuHelper/stuhelper/blob/develop/docs/development/storage-module.md)。

项目使用 [AGPL-3.0-only](LICENSE)。
