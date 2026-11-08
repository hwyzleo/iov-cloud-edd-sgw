# iov-cloud-edd-sgw

开源车联网企业数字底座服务网关（EDD-SGW）。

## 模块

```
iov-cloud-edd-sgw
├── edd-sgw-api        # 管理接口契约（Feign + VO），供 MPT 依赖
└── edd-sgw-service    # WebFlux 网关运行时与管理接口实现
```

- `edd-sgw-api` 依赖 OpenIOV `api` parent，`edd-sgw-service` 保持轻量 `cloud` parent（WebFlux 运行时）。
- 管理接口基路径：`/api/service/sgw/v1`，响应统一为 `ApiResponse<T>` / `PageResult<T>`。

## 已实现能力（EDD-SGW-DSN-CR-001）

- 结构化路由与策略草稿：路由、认证授权、流量治理、灰度策略的增删改查、复制、校验与物理分页。
- 不可变配置版本：发布前完整校验（引用、优先级歧义、目标合法性、权重合计、灰度键可用性），版本快照 + SHA-256 校验和，版本差异对比、回滚。
- 集群发布协议：Nacos 仅承载版本指针（版本号/发布ID/校验和）；实例从 MySQL 加载快照、侧路校验与编译、原子激活、逐实例 ACK；启动加载与就绪探针；发布超时扫描；失败发布重试（不新建版本）。
- 请求链路：请求级单一快照、请求ID、身份头清洗、CIAM RS256 本地验签（按 `kid` 缓存、未知密钥刷新、容忍时限）、客户端类型/scope/`perm:` 权限点授权、Redis 集群限流、Resilience4j 并发隔离与熔断、超时、安全方法重试、灰度加权哈希、路径与请求头变换、统一错误契约。
- 管理安全与审计：MPT 请求 HMAC 签名（方法 + 路径 + 请求体 SHA-256 + 时间戳 + nonce）+ Redis 防重放；配置变更审计（操作者/动作/前后值/结果/请求ID）。
- 导出：结构化配置导出，不包含任何密钥或令牌签发凭据。

## 本地构建与测试

```bash
mvn clean package          # 编译、单元测试、集成测试
mvn -pl edd-sgw-service -am test -Dtest=SgwFoundationIT   # 仅集成测试
```

集成测试使用本机 MySQL（自动创建 `db_sgw_it`，Flyway 迁移）、本机 Redis（db 15）、本地模拟上游与 JWKS 服务；JVM 时区必须为 UTC（`-Duser.timezone=UTC`，surefire 已配置）。

## 运行依赖

- Nacos：服务发现 + 配置（版本指针 Data ID 默认 `edd-sgw-config-version`）。
- MySQL：`db_sgw`，Flyway 管理表结构（`V1` 历史 + `V2` 基础设计）。
- Redis：集群限流与内部请求防重放。
- CIAM：JWKS 与令牌声明契约（见设计 §2；对应 CIAM CR 未交付前，需在环境中提供等价 JWKS 与声明）。

关键环境变量：

| 变量 | 说明 |
|------|------|
| `SGW_DIRECT_UPSTREAM_HOSTS` | 获批直连主机清单（逗号分隔，支持 `*.domain`） |
| `SGW_TRUSTED_PROXY_CIDRS` | 可信代理网段（决定是否采用 `X-Forwarded-For`） |
| `SGW_INTERNAL_SECRET` | MPT 内部请求 HMAC 密钥 |
| `SGW_CIAM_ISSUER` / `SGW_CIAM_JWKS_URI` | CIAM 签发者与 JWKS 地址（支持 `lb://`） |
| `SGW_PUBLICATION_DEADLINE_SECONDS` | 实例确认超时（秒） |
| `SGW_POINTER_STORE` | 版本指针存储：`nacos`（默认）/`memory`（测试） |

## 管理请求签名

MPT 调用管理接口时必须携带：

| 头 | 内容 |
|----|------|
| `X-Internal-Client` | 已登记的内部客户端ID（如 `mpt`） |
| `X-Internal-Timestamp` | 毫秒时间戳，需在允许窗口内 |
| `X-Internal-Nonce` | 单次随机串，Redis 防重放 |
| `X-Internal-Signature` | `HMAC-SHA256(secret, method\npath\nbodySha256\ntimestamp\nnonce\nclient)` 的小写十六进制 |
| `X-Internal-Actor` | 操作者（用于审计） |

## 构建与部署（Jenkins）

`Jenkinsfile` 已按多模块服务对齐 MPT/VMD 流水线：

- 目录：`DIR_KEY`（默认 `edd-sgw`）→ `edd-sgw-api`、`edd-sgw-service`
- `DEPLOY_API=true`：构建并发布 `edd-sgw-api` 到 Maven 仓库（MPT 依赖该制品，首次发布或契约变更时必须执行）
- 镜像构建：以 `edd-sgw-service` 为构建上下文，默认使用 `/var/jenkins_home/ServiceDockerfile`
  （需要网关专用运行时可通过 Job 环境变量 `SGW_DOCKERFILE` 覆盖）
- 可执行 Jar 位于 `edd-sgw-service/target/edd-sgw-service-*.jar`
- 发布顺序：`edd-sgw`（DEPLOY_API）→ `edd-sgw` 服务镜像 → `edd-mpt`

若继续使用 `GwDockerfile`，必须将其产物路径从原单模块 `target/*.jar` 调整为
`target/edd-sgw-service-*.jar`，且构建上下文为 `edd-sgw-service`。

## 参考文档

- 需求：EDD-SGW SPEC 需求（Notion `4120ec7a4b9280de9424c702eb77b23d`）
- 设计：EDD-SGW SPEC 设计（Notion `4120ec7a4b92806ab881def97399c817`）
- 设计变更：EDD-SGW-DSN-CR-001（Notion `4120ec7a4b928150a3bedcdb1642280f`）
- 数据库：EDD-SGW 数据库（Notion `4120ec7a4b9280ae8ec6c9a8740ff894`）
