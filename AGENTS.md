---
type: guide
status: Accepted
updated: 2026-11-21
---

# 存储贡献工程约定

遵循 [StuHelper 工作区工程约定](https://github.com/StuHelper/stuhelper/blob/develop/AGENTS.md)。本模块拥有贡献同意、条件、请求和任务、账本观测、审计、outbox 与迁移。经 storage 公开接口读取实例状态和应用贡献条件，供应商凭据由宿主管理。

先维护 `contracts/contribution.openapi.json`，再用 `make generate` 更新 SDK。服务端核验当前用户归属和动作权限。本人读接口可返回云盘原始空间，公开统计及运维接口使用经过筛选的字段。

在规格中登记新增场景，通过 `module.json` 的 `scenario_tests` 关联实际测试函数。使用独立 PostgreSQL 验证幂等、权限、并发、退出与恢复。供应商与身份测试使用专用夹具。
