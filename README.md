# Wharf

**把家里的机器和几台 VPS 当成一台来用。** 一条命令把本机代码部署到任意一台服务器，再一条命令给它挂上 HTTPS 域名；DNS、证书、跨机器的隧道全自动。你在页面上看，AI 在命令行里干活。

```bash
wharf deploy ./my-app --server home --apply            # 打包本机代码，在服务器上构建运行（自动识别 Python / Node / Go / 静态站）
wharf route add app.example.com --service my-app --apply   # 建 DNS、签证书、配网关，服务在没公网 IP 的家里机器上也行
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png">
  <img alt="总览" src="docs/screenshots/overview-light.png">
</picture>

> 个人项目，作者每天用它管自己的几台机器。版本 0.1，没有稳定性承诺；界面和文档目前只有中文。

## 为什么用它

**域名这件事不用再想。** 服务在 A 机器、公网入口在 B 机器、A 还没有公网 IP——这些 Wharf 自己判断：能走内网就直连，不行就自动起反向隧道，DNS 记录和证书一起配好。主入口那台机器挂了，可以配一个备用入口，DNS 自动切过去。

**打不开时，告诉你断在哪一层。** `wharf doctor app.example.com` 沿着 解析 → HTTPS → 网关 → 网关连上游 → 容器 一层层查，直接指出第一个不通的地方，不用再挨个 ssh 上去猜。

**数据跟着服务走。** `wharf service move blog --to vultr` 同步数据、在新机器启动、网关改指，域名不变。`wharf backup enable` 每天用 restic 备份到另一台机器，一条命令恢复。

**放心交给 AI。** 所有命令输出 JSON，任何改动先出计划再执行；删数据、覆盖、对公网开放这类高风险项，必须带 `--confirm` 才会执行，AI 拿到的令牌可以不给这个权限。装 CLI 时顺带装好 Skill，Claude Code、Codex 直接就会用——你只要说"把这个目录部署上去，挂到 app.example.com"。

**一眼看到哪里不对。** 每台机器对公网开放了哪些端口、归谁，没预期到的端口进待处理；容器被 OOM 杀掉、证书快到期、磁盘快满、域名打不开，推到飞书。

<table>
<tr>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/service-dark.png"><img alt="服务详情" src="docs/screenshots/service-light.png"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/domains-dark.png"><img alt="域名" src="docs/screenshots/domains-light.png"></picture></td>
</tr>
<tr>
<td align="center">服务：访问地址、容器、对公网开放的端口</td>
<td align="center">域名：指向、入口、登录保护、证书</td>
</tr>
</table>

<details>
<summary>全部功能</summary>

- **部署**：镜像、compose 文件、git 仓库、本机代码目录；有 Dockerfile 就用，没有按语言套模板；部署历史、回滚、固定镜像 digest 和 commit、有新版本自动更新；
- **域名**：自动建 DNS、签证书（含泛域名）；直连或反向隧道自动选；登录保护、按路径转发、跳转、限速和拦截扫描、备用入口、临时分享链接（`wharf share`）；
- **网关**：Caddy（要公网 IP 和 80/443）或 Cloudflare 隧道（不用开端口）；四层 TCP/UDP 转发；自定义错误页；
- **Cloudflare Workers / Pages**：导入、发布、版本回滚、绑定域名；
- **数据**：服务迁移、restic 备份恢复、数据卷文件浏览、控制面自身备份；
- **组网**：Tailscale 接入、机器间连通性和链路质量、服务之间按名字引用（`[[@db]]`）、出口代理、本机直连远端服务（`wharf connect`）；
- **运维**：容器和宿主机终端、日志、资源和请求曲线、定时任务、告警和飞书通知、对公网暴露面、机器基线、系统更新、一键升级；
- **给 AI**：`--json`、先 plan 再 apply、统一错误格式带下一步建议、令牌按权限点授权、操作审计。

</details>

## 适合谁

- 适合：一个人管几台 Linux 服务器（家里的机器、VPS），服务都跑在 Docker 里，域名托管在 Cloudflare；
- 不适合：多人协作和细粒度权限（页面只有一个管理员账号）、Kubernetes、非 Docker 的部署方式。

运行要求：

- 控制面和 agent 都以 Docker 容器运行，机器上要有 Docker；加入服务器时如果没有 Docker，脚本可以在 apt 系发行版上帮你装 `docker.io`（会先询问）；
- 用域名需要一个 Cloudflare 账号（DNS 托管在 Cloudflare）；
- Caddy 网关要求所在机器有公网 IP 并开放 80/443；没有公网 IP 时可以用 Cloudflare 隧道网关。

## 快速开始

### 1. 启动控制面

在一台有 Docker 的机器上：

```bash
docker run -d --name wharf-core --restart unless-stopped --network host \
  -v /var/lib/wharf-core:/var/lib/wharf-core \
  ghcr.io/wmgx/wharf-core:latest
```

打开 `http://<这台机器>:7700`，第一次进入要填初始化码并设置管理员账号：

```bash
docker exec wharf-core cat /var/lib/wharf-core/setup.code
```

常用环境变量：

| 变量 | 说明 |
|---|---|
| `WHARF_LISTEN` | 监听地址，默认 `0.0.0.0:7700` |
| `WHARF_PUBLIC_URL` | agent 连接控制面用的地址；不设置时用请求里的 Host |
| `WHARF_AGENT_IMAGE` | 加入命令里用的 agent 镜像，国内机器可以换成镜像站地址 |

忘记密码：`docker exec -it wharf-core wharf-core reset-password`。

### 2. 加服务器

在页面上点"新建 → 加服务器"，把给出的一条命令复制到目标机器上执行。agent 上线后会自动上报内网地址、公网 IP 和磁盘余量。

### 3. 部署服务、加域名

在页面上点"新建 → 部署服务"，选来源和服务器，可以顺手填域名。要用域名，先在"设置 → 厂商账号"里加一个 Cloudflare 账号（token 需要 Zone DNS 编辑、Zone 读取、Cloudflare Tunnel 编辑权限）。

### 4. 接入 CLI 和 AI

在"设置 → 访问令牌"里点"接入 CLI / AI"，新建 token，然后在你的电脑上执行一条命令，按提示粘贴 token 即可完成安装和登录：

```bash
curl -fsSL https://<控制面地址>/cli.sh | sh -s -- https://<控制面地址>
```

CLI 支持 Linux 和 macOS（amd64、arm64），版本和控制面一致；重复执行就是更新。

**给 AI 用**：脚本会顺带把 Skill 装到 `~/.agents/skills/wharf/`（Codex 等会读这个目录）；本机装了 Claude Code（有 `~/.claude`）时，再软链到 `~/.claude/skills/wharf/`。重复执行安装命令就会更新 Skill。其他工具可以从 `https://<控制面地址>/skill.md` 下载，内容和仓库里的 [`skill/SKILL.md`](skill/SKILL.md) 一致。

## 命令行

```bash
wharf status                                   # 总览
wharf deploy ./app --port http=8000 --apply    # 部署本机代码目录
wharf service deploy who --image traefik/whoami --port http=80 --apply
wharf route add who.example.com --service who --apply
wharf plan                                     # 只检查漂移
wharf apply <plan_id> --confirm <address>      # 执行计划，确认高风险项
wharf doctor who.example.com                   # 逐层诊断一个域名
wharf export > fleet.toml                      # 导出期望状态
wharf schema                                   # 字段说明（JSON Schema）
```

- 所有命令支持 `--json`，错误格式统一为 `{ code, message, hint, suggest }`；
- 退出码：`0` 成功，`1` 出错，`2` 需要确认，`3` 计划已过期，`4` 部分失败；
- 输出里不会出现密钥明文。

## 组成

| 程序 | 说明 |
|---|---|
| `wharf-core` | 控制面（axum + SQLite），提供 API 和页面，负责 plan / apply |
| `wharf-agent` | 每台服务器一个，主动连接控制面，执行 compose、网关、备份等操作 |
| `wharf` | 命令行 |

agent 和 CLI 到控制面的通道在应用层加密，不依赖 TLS。

## 安全须知

- 控制面能在所有服务器上起容器、改网关配置，开了宿主机终端或命令执行时还能直接操作宿主机，权限相当于这些机器的 root。建议只在内网或 Tailscale 里访问；要放到公网，经网关给它配 HTTPS 域名；
- agent 连接控制面时，公网地址必须用 `https://`，控制面会拒绝生成明文公网地址的加入命令；
- 页面登录有失败锁定，可以在"设置 → 登录与安全"里开两步验证；
- 访问令牌按权限点授权（查看、预览、执行、确认高风险、宿主机、管理），给 AI 的令牌不要带"确认高风险"和"管理"。

发现安全问题请见 [SECURITY.md](SECURITY.md)。

## 开发

需要 Rust（版本见 `deploy/Dockerfile`）和 Node 22。

```bash
# 控制面：数据放在 ./data，监听 7700
cargo run -p wharf-core

# 页面：开发服务器把 /api 代理到控制面（默认 http://127.0.0.1:7700）
cd web && npm ci && npm run dev
```

不先构建页面时，控制面二进制里不含页面，访问会得到提示，API 和 CLI 正常可用。

提交前的检查（和 CI 一致）：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cd web && npx tsc --noEmit

# 改了 crates/api-types 里给页面用的类型后，重新生成 web/src/types.gen.ts
cargo run -q -p wharf-cli -- schema web | node web/scripts/gen-types.mjs > web/src/types.gen.ts

scripts/build-images.sh    # 构建 wharf-core / wharf-agent 镜像
scripts/e2e.sh             # 在有 Docker 的机器上做端到端验证
```

欢迎提 issue。这是个人项目，功能取舍以作者自己的使用为准，较大的改动请先开 issue 讨论。

## 协议

[Apache-2.0](LICENSE)
