---
name: wharf
description: 用 wharf CLI 管理服务器、服务、域名、网关、备份和告警。适用于部署、排障、监控和维护。
---

# Wharf

用 `wharf` 操作，用户在页面查看。服务器（server）运行 agent，服务（service）是 Compose 项目，网关（gateway）是入口，路由（route）把域名经网关连到服务。

## 守则

1. 用 `--json` 读取机器结果。普通命令和参数错误输出一份 JSON。跟随日志、实时看执行输出时用文本模式。
2. 修改先出计划，把变更与影响给用户看。用户批准后执行 `wharf apply <计划ID>`，或重跑命令加 `--apply`。用户已经明确授权直接执行时可以一步 `--apply`。
3. 删除、覆盖、开放公网等需要确认时，把 `needs_confirm` 或错误 `details` 给用户看。获准后逐项加 `--confirm <地址>`。
4. 出错看 `code`、`message`、`hint`、`suggest`。按原因处理，避免重复提交同一变更。
5. 保护令牌和密钥。应用密码存入 `secret`，用 `[[NAME]]` 引用，文件挂载用 `[[FILE:NAME]]`。避免在对话、仓库和日志里留下明文。
6. 直接生效的任务、密钥、告警、令牌和备注操作，支持 `--dry-run` 时先预览。改动可加 `--reason '<原因>'`，计划可加 `--note '<备注>'`。
7. 宿主机执行、清理、基线调整、升级等操作先说明影响并取得授权。宿主机操作还需要令牌有 `host` 权限且服务器打开相应能力。
8. `--port`、`--path` 替换整个列表。单独增删用 `--add-port` / `--rm-port` 或 `--add-path` / `--rm-path`。

退出码：`0` 成功，`1` 出错，`2` 需确认，`3` 计划过期（重新 plan），`4` 部分失败。
`server exec` 和 `service exec` 发起成功后透传远端退出码，包括 JSON 模式。

## 登录和状态

让用户从页面“设置 → 访问令牌 → 接入 CLI / AI”复制安装登录命令。版本不一致时用 `wharf ops self-update` 更新 CLI 和已安装的 Skill。

```bash
wharf status --brief --json
wharf ops whoami --json
```

## 查服务和服务器

```bash
wharf service list --fields name,status.summary
wharf service show app --json
wharf server list -q
```

`--fields` 隐含 JSON，列表逐项取字段。`-q` 让列表每行只输出主键，计划和执行只输出 ID，等待静默。`-q` 与 JSON、筛选字段、分页和游标互斥。

## 部署、重启和回滚

```bash
wharf deploy ./app --server s1 --port http=8000 --json
wharf service deploy app --server s1 --image nginx:stable --port http=80 --json
wharf service deploy app --server s1 --compose ./compose.yml --port http=:8080 --json
wharf service show app --json
wharf service restart app --json
wharf service history app --json
wharf service rollback app --json
```

三个部署示例按来源选一个。本机目录可加 `--detect-only` 离线识别语言、Dockerfile 和默认端口。Compose 的容器端口写在文件里，`--port` 只填宿主机端口。
更新已有服务时只传要调整的参数。执行后检查 `service show` 和日志，回滚可用 `--to <部署记录ID>` 指定版本。

## 计划、执行和等待

```bash
wharf plan --json
wharf plan -f app.toml --partial --json
wharf plan list --pending --json
wharf plan show <计划ID> --json
wharf apply <计划ID> --json
wharf run show <执行ID> --json
wharf wait service app --json
```

局部意图文件用 `--partial`；完整意图会让未列出的对象进入删除计划。用 `wharf plan validate app.toml --json` 离线检查文件。

## 域名和排障

```bash
wharf route add app.example.test --service app --json
wharf doctor app.example.test --json
wharf service logs app --since 1h --errors --json
wharf route logs app.example.test --status 5xx --since 1h
wharf gateway logs gw --access --host app.example.test --since 30m
wharf server logs s1 --errors --json
wharf ops core logs --since 1h --errors --json
```

`doctor` 按解析、HTTPS、网关、上游和容器定位首个故障。`status` 的 `issues` 列待处理事项，按各项的 `hint` 排查。

## 按需查命令

- 用 `wharf commands <前缀>` 查参数和权限，尽量缩到相关命令。加 `--usable` 可按当前令牌筛选。旧版 CLI 用 `wharf <命令> --help` 查参数。
- 用 `wharf schema service deploy` 查命令说明，用 `wharf schema service_view --paths --json` 查返回字段。类型与命令同名时，查命令用 `wharf schema --command plan`。
- 服务文件、环境变量、监控、纳管和高级部署查 `wharf commands service`，可缩到 `service files`、`service env`；任务和产物查 `wharf commands ops task`。
- 证书、Caddy 和路由门禁查 `wharf commands route`；组网、连接和 OIDC 查 `wharf commands network`，如 `wharf schema network sso oidc`。
- 备份、迁移和清理查 `wharf commands data`；导入、导出和意图校验查 `wharf commands plan`。恢复或删除数据前先核对来源、目标和影响，向用户取得确认。
- 通知、令牌和控制面维护查 `wharf commands ops`，可缩到 `ops notify`、`ops token`、`ops core`。
- 资源曲线、审计、引用和拓扑查 `wharf commands inspect`。全局键用 `config list`、`config get <键>`、`config set <键> <值>`、`config unset <键>`；专用模板查 `wharf commands config defaults`。
