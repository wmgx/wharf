---
name: wharf
description: 用 wharf 命令行管理自己的服务器、服务、域名、网关、备份和告警。用户提到部署服务或代码、发布新版本、加域名、域名打不开、看日志、重启或回滚服务、迁移服务、备份恢复、服务器端口暴露、待处理事项，或者直接提到 wharf 时使用。
---

# Wharf

Wharf 是一个人用的多服务器管理系统。你通过 `wharf` 命令行操作，用户在页面上查看。

四个概念：

- **服务器**（server）：每台机器跑一个 agent；
- **服务**（service）：一个 compose 项目，来源是镜像、compose 文件、git 仓库或本机代码目录；
- **网关**（gateway）：公网入口，Caddy 或 Cloudflare 隧道；
- **路由**（route）：域名 → 网关 → 服务。

## 守则

1. **加 `--json` 读取机器结果。** 普通命令输出一份 JSON，参数错误也一样。跟随日志需要连续输出时用文本模式。
2. **先计划，再执行。** 修改类命令不带 `--apply` 时只生成计划，先把计划给用户看；用户同意后再 `wharf apply <plan_id>`，或者重新执行原命令加 `--apply`。用户已经明确说“直接做”时可以一步 `--apply`。
3. **高风险项不要自己确认。** 计划里标了需要确认的项（删数据、覆盖、对公网开放等），执行时会以退出码 `2` 拒绝。把这些项原样告诉用户，用户同意后才能加 `--confirm <地址>`。需要确认的地址在 `needs_confirm` 里。用 `--apply --json` 或 `wharf apply --json` 遇到拦截时，看错误的 `details` 获取计划编号、待确认项及原因。用 `wharf plan show <id>` 回查计划，用 `wharf plan list --pending` 列出可执行的计划。
4. **出错先看 `hint` 和 `suggest`。** 错误格式是 `{ code, message, hint, suggest }`，按提示改，不要盲目重试同一条命令。
5. **字段不要猜。** 参数不确定时看 `wharf commands [命令前缀]`（全部命令和参数的 JSON，例如 `wharf commands service`）或 `wharf <命令> --help`；用 `wharf commands --usable` 按令牌权限筛选。对象字段用 `wharf schema <类型> --paths --json` 查看。
   结果太长时用 `--fields` 只取要的字段，例如 `wharf service list --fields name,status.summary`（隐含 `--json`）；拼错字段会报错，可能缺失的字段加 `?`，例如 `note?`。列表太长再加 `--page-size 20 --page 2`，分页信息在 `pagination`，顶层数组改从 `items` 读取。
   反复查同一件事时加 `--changed=<游标>`。默认不比较延迟和观测时间等高频字段，需比较时加 `--include-volatile`。旧写法 `--changed` 使用默认游标。
   `wharf whoami --json` 看当前 token 的权限；提示本机 wharf 和控制面版本不同时运行 `wharf self-update`，再用 `wharf commands --changes` 看新版本多了哪些命令和参数。
   要等部署完成、服务恢复、告警解除时用 `wharf wait`，不要自己循环查：`wharf wait service <服务>`、`wharf wait route <域名>`、`wharf wait clear --subject <服务>`，默认最多等 10 分钟（`--timeout`）。
6. **不打印、不写入 token 和密钥。** 服务要用的密码放进密钥（`wharf secret`），环境变量里用 `[[NAME]]` 引用。`[[url:NAME]]`、`[[b64:NAME]]`、`[[json:NAME]]` 用于编码，`[[FILE:NAME]]` 用于服务里的只读文件挂载，引用会替换为容器内路径。
7. **直接生效的命令先预览。** `wharf task add/rm`、`wharf secret set/rm`、`wharf alert set`、`wharf token set`、`wharf service note`、`wharf server note`、`wharf route note` 不走计划，先加 `--dry-run` 看会改什么。
   修改时加 `--reason "<为什么>"`，生成计划时可以加 `--note "<备注>"`，都会记进操作记录。
8. **宿主机命令要用户同意。** `wharf exec <服务器> -- '<命令>'`、`wharf server prune`、`wharf server baseline <服务器> --apply` 这类直接动机器的操作，先说明要做什么。

退出码：`0` 成功，`1` 出错，`2` 仅用于 `ConfirmRequired`，`3` 计划已过期（重新 plan），`4` 部分失败。`wharf exec` 和 `wharf service exec` 执行成功发起后透传远端命令退出码，`--json` 也一样。

- `wharf service render <服务>` 预览展开后的 Compose，密钥会打码。
- `wharf service logs <服务> --container <名>` 和 `wharf service restart <服务> --container <名>` 指向单个 Compose 子容器。
- `wharf service exec <服务> --container <名> -- '<命令>'` 在容器内执行。宿主机和容器 exec 都可用 `--script <文件|->`，文本模式默认实时输出。
- 保留 `--port` / `--path` 全量替换行为，只增删一项时用 `--add-port` / `--rm-port` 或 `--add-path` / `--rm-path`。
- `wharf task set <任务>` 只读查看，传修改参数可局部更新。`task enable` / `task disable` 切换启用状态。`task run --no-wait --env K=V` 返回运行记录 ID，可用 `task logs <任务> --run <ID>` 查看或用 `task cancel <ID>` 取消。

## 开始前

```bash
wharf status --brief --json  # 服务器、服务、网关、路由；需要注意的事项看 issues
```

没有登录或连不上控制面时，让用户在页面“设置 → 访问令牌 → 接入 CLI / AI”里拿安装登录命令，不要自己找 token。

给 AI 签发访问令牌时，建议用 `--expires 30d` 设置有效期，用 `--from <地址或网段>` 限制来源；`--services blog,halo` 可以限定可操作的服务。
管理员用 `wharf token set <名称>` 修改这些限制或 `--perms`。用 `--unset-expires`、`--unset-from`、`--unset-services` 分别清除三项限制。
管理员可用 `wharf token explain <名称> [--service 服务] [--from IP]` 只读推演常用操作的令牌判定，也可同时传 `--method` 和 `--path` 推演指定请求的令牌层。

用 `wharf service note <服务>`、`wharf server note <服务器>`、`wharf route note <域名>` 查看公开备注。加文本修改，加 `--clear` 清除公开部分。页面加密的私密内容会保留，`has_sealed_note` 表示还有私密内容。

## 常见任务

### 查列表、日志和服务文件

列表筛选可组合。服务支持 --server、--status、--no-backup、--has-update、--brief。路由支持 --gateway、--service、--public、--internal、--unprotected。服务器支持 --online、--offline、--outdated，网关支持 --server、--kind。

-q 让列表每行输出一个主键，计划与执行只输出 ID，等待期间静默。-q 与 --json、--fields、--page-size、--changed 互斥。

    wharf service list --server s1 --status abnormal -q
    wharf route list --unprotected -q
    wharf service logs app --grep panic -C 3 --exclude healthcheck
    wharf service logs app --grep '50[0-4]' --regex --since 2h --until 1h
    wharf gateway logs gw --where 'status>=500' --cols time,method,path,status
    wharf service files ls app config
    wharf service files tail app logs/app.log -n 50
    wharf service files grep app ERROR config --limit 20
    wharf service files mkdir app data/tmp -p
    wharf service files mv app data/tmp/a data/tmp/b
    wharf service files rm app data/tmp/b

日志上下文可以用 -A 或 -B 单独调整，执行日志支持上下文、排除和正则。--where 可重复，所有条件同时匹配。带 --until 的容器日志查询需要新版 agent。

文件查看需要 read 权限。建目录、移动和删除需要 exec 权限，直接执行并记审计。--force 允许覆盖目标，--recursive 允许递归删除。

    wharf wait server s1 --online-only
    wharf wait dns app.example.test --all
    wharf wait cert app.example.test --timeout 5m

wait server 默认同时检查网关、链路和运行中的容器。wait dns 默认复用 DNS 生效判定，--all 要求全部解析器一致。wait cert 以 HTTPS 握手取得的证书为准。

### 部署

```bash
# 本机代码目录：自动识别 Python、Node、Go、静态站点，有 Dockerfile 就用。再次执行就是发布新版本
# 不给 --port 时 Python 用 8000、Node 用 3000，其余 8080；只想看用哪个 Dockerfile 加 --print-dockerfile
wharf deploy ./app --port http=8000 --json

# 离线看语言、Dockerfile 和默认端口
wharf deploy ./app --detect-only --json

# 镜像
wharf service deploy blog --server <服务器> --image ghcr.io/x/blog:latest --port http=80 --json

# compose 文件：--port 只填宿主机端口，容器端口写在 compose 里
# --port 替换全部端口，按名称增删请用 --add-port / --rm-port
wharf service deploy blog --server <服务器> --compose ./compose.yml --port http=:8080 --json

# git 仓库
wharf service deploy blog --server <服务器> --git https://github.com/x/blog --port http=8000 --json

# 照着文档里的 docker run 命令：端口、环境变量、数据卷、资源上限一起转过来，没转换的参数打在标准错误里
# JSON 模式的转换提醒看 plan.warnings（仅生成计划时直接看 warnings）
wharf service deploy blog --server <服务器> --from-run 'docker run -d -p 8080:80 -v data:/data nginx' --json

# compose 文件的网址（在本机下载，GitHub 网页链接自动换成原始文件）
wharf service deploy blog --server <服务器> --compose-url https://github.com/x/blog/blob/main/compose.yml --json
```

已存在的服务再执行 `service deploy` 只改给出的参数。部署后用 `wharf service show <服务> --json` 确认状态。

配置文件（应用靠配置文件而不是环境变量时用）：内容存在 Wharf 里，部署时放进容器，跟着部署历史和回滚走。
不要让用户自己往数据目录里放配置文件。容器里是只读的，应用自己改写的内容下次部署会被覆盖。

```bash
wharf service file <服务> --json                                   # 列出
wharf service file <服务> /etc/app/config.yaml                     # 打印内容
wharf service file <服务> /etc/app/config.yaml --file ./config.yaml --json   # 新增或替换，出计划；--file - 读标准输入
wharf service file <服务> /etc/app/config.yaml --rm --json         # 去掉
```

内容里可以写 `[[密钥名]]`（只替换存在的密钥，TOML 的 `[[servers]]` 不受影响）和 `[[@服务]]`。

更新和回滚：

```bash
wharf service update <服务> --json      # 查新版本（镜像标签或分支的最新 commit）
wharf service history <服务> --json     # 部署历史
wharf service rollback <服务> --json    # 回到上一个不同的版本，--to <部署记录 id> 指定
wharf service restart <服务> --json     # 只重启容器，不改配置
```

`update`、`rollback` 不带 `--apply` 时只出计划，同样按守则 2 处理。

### 加域名

```bash
wharf route add blog.example.com --service blog --json
```

DNS 记录、证书、网关配置都会自动处理，前提是用户已经在页面上加了 Cloudflare 账号。网关和服务不在同一台机器时会自动选直连或反向隧道。对已有域名再执行 `route add` 只改给出的参数，门禁等其余设置保留。

按路径拦截、加响应头这类网关规则：`wharf route caddy <域名> --file -` 写一段 Caddy 配置，插进这个域名的站点块；不带参数查看现状，`--off` 去掉。
新域名 HTTPS 打不开、证书还没签下来：`wharf route cert <域名>` 看申请状态、失败原因和下次自动重试时间；`--retry` 让入口立刻重新申请（1 分钟内只能一次）。

换默认入口：`wharf gateway add <入口> --default`，旧的默认入口会在同一个计划里取消。

要加登录保护：`wharf route sso <域名> --help`。博客这类公开站点不要加门禁；应用后台想免密进入时，用 `--mode login --public`，登录步骤文件里用 `entry` 写后台路径。

应用支持 OIDC 时优先用 OIDC（比代登录稳）：

1. `wharf route sso <域名> --mode oidc --redirect <回调路径> --apply`，回调路径看应用的 OIDC 文档；公开站点加 `--public`，私有站点不加（门禁和 OIDC 一起生效）。
2. `wharf sso oidc <域名> --json` 拿 issuer、client_id、secret_ref。
3. 把它们写进服务环境变量，密钥原样写 secret_ref（如 `[[OIDC_BLOG_EXAMPLE_COM]]`），不要读出明文；scope 用 `openid profile email`，要角色映射时加 `groups`（值是 `["admin"]`）。
4. 重新部署服务。很多应用要求邮箱，`wharf sso oidc` 显示邮箱没设时让用户在页面设置，或 `wharf sso email <邮箱>`。

### 域名打不开

```bash
wharf doctor blog.example.com --json
```

它会逐层检查：解析 → HTTPS → 网关 → 网关连上游 → 容器，并指出第一个不通的层。按那一层继续查：

- 容器：`wharf service show <服务> --json`、`wharf service logs <服务>`；
- 域名访问日志：`wharf route logs blog.example.com --status 5xx --since 1h`，可加 `--path /api/`、`--method POST`、`--tail`、`--json`；
- 网关访问日志：`wharf gateway logs <网关> --access --host blog.example.com --since 30m`，也支持 `--status`、`--path` 和 `--method`；
- 网关容器日志和配置：`wharf gateway logs <网关> --since 1h --errors`、`wharf gateway config <网关>`。也可用 `--grep` 和 `--max-line` 筛选容器日志；
- 解析和证书：一般是 Cloudflare 账号权限或 DNS 还没生效，把 `hint` 告诉用户。

要从指定机器检查单个目标，用 `wharf server probe <服务器> <域名|主机:端口|HTTP(S) URL> --json`。
要从服务容器的网络检查单个目标，用 `wharf service probe <服务> <目标> --json`，多容器服务用 `--component <组件名>` 指定容器。

### 看日志和资源

```bash
wharf service logs <服务> --tail 200
wharf service logs <服务> --since 2h --errors --json      # 只看报错，同一种合成一条带次数，先用这个
wharf service logs <服务> --grep timeout --tail 50       # 按关键字筛，--max-line 限制每行长度
wharf service logs <服务A> <服务B> --since 30m            # 给多个服务名，按时间合看
wharf server logs <服务器> --errors --json   # Wharf 自己：这台机器上 agent 的日志
wharf core logs --since 1h --errors --json   # Wharf 自己：控制面的日志
wharf service files <服务> [目录] --json     # 服务数据目录（/srv/<服务>/）里的文件；download 下载，upload 上传（覆盖，要用户同意）
wharf service timeline <服务> --json    # 部署、备份、重启、告警按时间排
wharf metrics <服务器或服务> --range 24h --json   # 资源曲线
wharf server disk <服务器> --json        # 磁盘被哪个服务占了（数据、日志、数据卷），--measure 现测
wharf server host <服务器> --json        # 镜像、构建缓存、容器日志、journal 的占用
```

### 迁移和备份

```bash
wharf service move <服务> --to <服务器> --json             # 同步数据、新机器启动、网关改指，域名不变
wharf backup enable <服务> --to <备份机> --exclude 'data/cache/**' --keep-daily 7 --json
wharf backup set <服务> --json
wharf backup set <服务> --unset-exclude 'data/cache/**' --unset-retention --json
wharf backup run <服务> --keep --note '升级前留底' --json
wharf backup list <服务> [--from <备份机>] --json
wharf backup ls <服务> [目录] [--snapshot <快照>] --json
wharf backup extract <服务> <文件> -o <本地路径> --json
wharf backup diff <服务> [--base <旧快照>] [--snapshot <快照>] --json
wharf backup keep <服务> <快照> [--off] [--note <备注> | --unset-note] --json
wharf backup unlock <服务> --from <备份机> --stale-only --json
wharf backup core --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --json
wharf backup core --verify-password --json    # 交互输入登录密码，核验 HTTP 认证、仓库解密和快照
wharf backup core --export -o <文件> --json    # 交互输入登录密码，下载离线加密灾备包
wharf backup move <服务> --to <新备份机> --dry-run --json
wharf backup move <服务> --to <新备份机> --json  # 控制面仓库把服务名替换为 --core
# 恢复会停服务并覆盖数据（原数据改名保留），必须先问用户，用户同意后：
wharf backup restore <服务> --snapshot <快照 id> --confirm service/<服务> --json
```

整机灾备先用 `wharf-core restore --from <备份机地址> --user <管理员>` 或 `--recovery-key <文件>`，随后用 `wharf-core --safe-mode` 启动。核对节点和备份目标后执行 `wharf core resume --json`。

仓库迁移中断后重跑同一条命令即可续传。目标机已有仓库时按预检提示确认归档。源仓库保留，由 `wharf data cleanup` 统一管理。

在新机执行 `wharf-core restore --file <文件>`，输入导出时的登录密码。数据目录已有控制面文件时，确认归档后加 `--yes`。恢复后以 `WHARF_SAFE_MODE=1` 启动控制面，核对节点和备份目标，再执行 `wharf core resume`。

### 让服务或脚本发通知

用户的服务、脚本要发通知（备份完成、任务出错）时，不要自己接飞书，用 Wharf 的通知地址，消息走 Wharf 已配置的渠道：

```bash
wharf notify key add <名字> --json   # 地址存进密钥 NOTIFY_URL_<名字>，服务环境变量写 [[NOTIFY_URL_<名字>]]
wharf notify key list --json
```

调用方式：`curl -d '消息' "$NOTIFY_URL"`，或者发 JSON `{"title": "...", "text": "..."}`。每个凭证每分钟最多 20 条。
Wharf 以外的机器上的脚本要用地址时才加 `--show` 打印出来，地址就是凭证，不要写进仓库。

### 处理“需要注意”

`wharf status --json` 里的 `issues` 各带 `code`、`title`，有的还带 `hint`（给命令行的处理办法），先照 `hint` 做。常见的：

- **未确认的公网端口**：`wharf server exposure <服务器> --json` 看端口归属。加 `--refresh` 重新检查。是用户预期开放的，用户同意后用 `--ack tcp/6379` 这样的格式标记为已知（也可以在页面上点“我知道”）；不该开放的，改服务的端口配置或让用户在防火墙上关掉。
- **服务异常、域名不通**：按上面“域名打不开”的流程查。
- **agent 版本落后**：`wharf upgrade` 会升级控制面和所有 agent，先问用户。

### 服务监控

用 `wharf describe service` 查询服务命令和参数。

- `wharf service log-alert <服务>` 查看规则、最近命中和触发状态。用 `add <pattern> [--regex] [--window 5m] [--count 1] [--container <Compose 服务名>]` 添加，用 `rm <序号或pattern>` 删除一条，或用 `--off` 关闭全部。
- `wharf service port-check <服务> <端口名>` 查看当前检查，加 `--on` 启用或恢复 TCP 检查。已发布的 TCP 端口默认启用。UDP 用 `--udp-dns <域名>` 或 `--udp-send <hex> --udp-expect <hex>` 配置，用 `--off` 关闭检查。
- `wharf service heartbeat <服务> --every 10m [--grace 5m]` 开启心跳，用 `--off` 关闭。心跳已开启时可单独调整 `--every` 或 `--grace`。容器重新部署后通过 `WHARF_HEARTBEAT_URL` 获得报到地址，失败时请求该地址的 `/fail`。控制面需设置 `WHARF_PUBLIC_URL`。用 `wharf service heartbeat <服务>` 看配置与最近报到，显式加 `--reveal` 查看完整地址。用 `--rotate` 生成轮换口令的部署计划，保留报到历史。
- 以上配置变更默认生成计划。确认后用 `--apply` 执行。日志和端口检查、心跳间隔和宽限调整仅写配置。开启或关闭心跳会触发部署。用 `wharf alert list` 看告警规则和通知开关。

### 已有容器纳管

```bash
wharf service discover <服务器> --json   # 还没纳管的容器
wharf service import <服务器> --project <compose 项目名> --json   # 或 --container <容器名>
```

用 `wharf service unmanaged-ignore <服务器> --project <项目>` 忽略提示和通知。独立容器用 `--container <容器名>`，加 `--undo` 取消忽略。

导入同样先出计划，按守则 2 处理。

## 不确定时

- 不知道有什么命令：`wharf --help`、`wharf <命令> --help`；
- 想看完整期望状态：`wharf export`；只改一个服务时 `wharf export --service <服务> -o x.toml`，改完 `wharf validate x.toml`（不连控制面），再 `wharf plan -f x.toml --partial`（只动文件里写到的对象；不加 `--partial` 会删掉文件里没写的）；
- 想知道最近谁做了什么：`wharf audit --json`。

- `wharf service monitor <服务>` 和 `wharf service auto-update <服务>` 无修改参数时只读查看。加 `--on` 开启或加 `--off` 关闭，确认后可加 `--apply` 执行。例如 `wharf service auto-update <服务> --on --apply`。用 `wharf service monitor <服务> --unset-expect` 清除预期状态码。
- `wharf server watch-unit <服务器> <unit>` 无修改参数时只读查看。加 `--on` 开启或加 `--off` 关闭，直接生效。

### 引用、配置和体检

- 用 `wharf refs service/<服务>` 查引用，用 `wharf tree [目标]` 看拓扑，用 `wharf search <词> --kind <类别>` 查配置。密钥引用用 `wharf secret refs <名称>`，无引用的业务密钥用 `wharf secret unused` 查看。
- 用 `wharf config` 列配置，`config get <键>` 查看一项，`config set <键> <值>` 或 `config unset <键>` 修改。
- `wharf secret import .env --dry-run` 预览批量导入。默认有冲突时整批拒绝，加 `--only-missing` 跳过或用 `--overwrite` 覆盖。用 `wharf secret list --prefix <前缀>` 筛名称。
- `wharf service env sync <服务> .env` 预览变量差异。确认后加 `--apply`，敏感值默认转存为密钥。要保留明文时指定 `--plain <键>`。
- `wharf task artifacts <任务> [--run <编号>]` 列产物，用 `--get <相对路径> -o <文件>` 下载。
- `wharf audit --since 24h --target service/<服务> --errors` 只看近期失败，可再加 `--until` 或 `--status`。
- `wharf lint` 有错误时退出码为 1，`--strict` 时警告也算失败。意图目录可用 `wharf validate ./fleet.d/` 和 `wharf plan -f ./fleet.d/`。
