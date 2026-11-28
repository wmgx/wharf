---
name: wharf
description: 用 wharf CLI 管理服务器、服务、域名、网关、备份和告警。适用于部署、排障、监控和维护。
---

# Wharf

用 `wharf` 操作，用户在页面查看。服务器（server）运行 agent，服务（service）是 Compose 项目，网关（gateway）是入口，路由（route）把域名经网关连到服务。

## 守则

1. 用 `--json` 读取机器结果。普通命令和参数错误输出一份 JSON。跟随日志、实时看执行输出时用文本模式。
2. 先用 `wharf commands <命令前缀>` 查 `effect` 和 `flag_variants`。对 `plan` 操作，先省略 `--apply` 生成计划。执行计划或 `--apply` 会立即提交变更，先用 `wharf plan show <计划ID> --json` 查看影响并取得授权。
3. 删除、覆盖、开放公网等需要确认时，把 `needs_confirm` 或错误 `details` 给用户看。获准后逐项加 `--confirm <地址>`。
4. 出错看 `code`、`message`、`hint`、`suggest`。按原因处理，避免重复提交同一变更。
5. 保护令牌和密钥。应用密码存入 `secret`，用 `[[NAME]]` 引用，文件挂载用 `[[FILE:NAME]]`。避免在对话、仓库和日志里留下明文。
6. `direct` 写操作会直接执行，即使省略 `--apply`。先用同组的 `show`、`list`、`get` 或明确说明为只读的预览核对对象与影响，再取得授权。遇到带标志才写入的命令，先用 `wharf schema <命令路径>` 核对参数说明。改动可加 `--reason '<原因>'`，计划可加 `--note '<备注>'`。
7. 宿主机执行、清理、基线调整、升级等操作先说明影响并取得授权。宿主机操作还需要令牌有 `host` 权限且服务器打开相应能力。
8. `--port`、`--path` 替换整个列表。单独增删用 `--add-port` / `--rm-port` 或 `--add-path` / `--rm-path`。

退出码：`0` 成功，`1` 出错，`2` 需确认，`3` 计划过期（重新 plan），`4` 部分失败。
`server exec` 和 `service exec` 发起成功后透传远端退出码，包括 JSON 模式。

## 登录和状态

让用户先在页面“设置 → 访问令牌 → 接入 CLI / AI”核对控制面和令牌权限。运行安装登录命令会立即写入本机。用 `wharf ops whoami --json` 核对 `cli_build` 和 `core_build`，再按需执行 `wharf ops self-update`。该命令会立即更新本机 CLI 和已安装的 Skill。

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

## 部署和回滚计划

```bash
wharf deploy ./app --server s1 --port http=8000 --json
wharf service deploy app --server s1 --image nginx:stable --port http=80 --json
wharf service deploy app --server s1 --compose ./compose.yml --port http=:8080 --json
wharf service show app --json
wharf service history app --json
wharf service rollback app --json
```

三个部署示例按来源选一个。本机目录可加 `--detect-only` 离线识别语言、Dockerfile 和默认端口。Compose 的容器端口写在文件里，`--port` 只填宿主机端口。
更新已有服务时只传要调整的参数。执行后检查 `service show` 和日志，回滚可用 `--to <部署记录ID>` 指定版本。

`wharf service restart app --json` 会立即重启指定服务，省略 `--apply` 也会执行。先用 `wharf service show app --json` 和 `wharf inspect refs service/app --json` 核对运行状态和依赖，再获准重启。

## 计划、执行和等待

```bash
wharf plan --json
wharf plan -f app.toml --partial --json
wharf plan list --pending --json
wharf plan show <计划ID> --json
wharf run show <执行ID> --json
wharf wait service app --json
```

局部意图文件用 `--partial`；完整意图会让未列出的对象进入删除计划。用 `wharf plan validate app.toml --json` 离线检查文件。

核对 `plan show` 并取得授权后执行 `wharf apply <计划ID> --json`，它会立即启动执行。随后用 `run show` 和 `wait service` 检查结果。

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
- 备份、迁移和清理查 `wharf commands data`。用 `wharf schema data backup restore` 查恢复参数，用 `wharf data backup list app --json` 和 `wharf data backup diff app --snapshot <快照ID> --json` 核对快照和影响。恢复命令在确认参数满足后会立即停服务并恢复数据。恢复或删除数据前先向用户取得确认。导入、导出和意图校验查 `wharf commands plan`。
- 通知、令牌和控制面维护查 `wharf commands ops`，可缩到 `ops notify`、`ops token`、`ops core`。
- 资源曲线、审计、引用和拓扑查 `wharf commands inspect`。用 `wharf config list` 或 `wharf config get <键>` 核对当前配置。`wharf config set <键> <值>` 和 `wharf config unset <键>` 会立即修改全局配置。专用模板查 `wharf commands config defaults`。
