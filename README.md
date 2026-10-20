# Wharf

个人多服务器管理：服务器、服务、网关、路由。AI 用 `wharf` CLI 操作，人用页面查看和部署。

- `wharf-core`：控制面（axum + SQLite），提供 API，负责 plan / apply；
- `wharf-agent`：每台服务器一个，主动连接控制面，执行 compose 和网关操作；
- `wharf`：命令行，所有命令支持 `--json`，修改先 plan 再 apply。

```bash
cargo test --workspace     # 单元测试
scripts/build-images.sh    # 构建 wharf-core / wharf-agent 镜像
scripts/e2e.sh             # 在有 Docker 的机器上做端到端验证
```

## 协议

[Apache-2.0](LICENSE)
