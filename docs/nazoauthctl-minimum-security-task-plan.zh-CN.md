# NazoAuthCtl 过度校验收敛与运营能力简化任务计划书

> 文档性质：可直接交给实现代理逐项执行的唯一任务清单  
> 编制日期：2026-08-24  
> 研究快照：NazoAuthCtl `82fbf5ad225e95f149ece4a927df1fd37155e704`（基线 `origin/main` 为 `775abde2c5d861763a0609a43d656fa9655ce592`）；NazoAuth `688c1e831c516e48fe6a6b73ded43e8a450d468a`  
> 涉及仓库：`D:\self\NazoAuthCtl`、`D:\self\NazoAuth`；`D:\self\NazoAuthWeb` 只做回归确认，不修改  
> 当前状态：计划完成，尚未实施代码修改

## 1. 状态标记规则

- `[]`：尚未开始。
- `[ - ]`：正在执行。开始某项任务前，必须先把该任务标题前的 `[]` 改成 `[ - ]`，再修改代码。
- `[ x ]`：该任务的代码、删除项、测试、文档、迁移证据和回滚检查全部完成。任一证据缺失均不得标记为 `[ x ]`。
- 任一时刻只能有一个 `[ - ]`。任务存在依赖，不得跨项并行修改同一调用链。
- 阻塞时保留 `[ - ]`，在该任务的“执行证据”下追加 `BLOCKED:`、原始错误、已核实事实和所需决策；不得把阻塞写成完成。
- 完成一项时，在同一提交中把 `[ - ]` 改为 `[ x ]`，并填写提交 SHA、命令、退出码、测试摘要、CI 链接和工作树状态。
- 不得删除、重排或合并任务来制造完成状态。调查若推翻本计划前提，停在当前任务提交差异报告，不得自行恢复旧的复杂体系。

## 2. 正确定位

`nazoauthctl` 可以并且应当成为 NazoAuth 的运营、治理与灾备工具，也可以跨主机执行。问题不在于这些能力本身，而在于当前设计经常没有复用已经成立的信任边界：

- 本机已经通过 OS 用户、文件权限、sudo/root 或容器运行时权限完成认证与授权，ctl 又要求 controller、receipt、audit、break-glass 多套身份重复证明“你是你”。
- 跨主机已经通过 SSH host key、SSH 用户公钥/agent 和远端 sudo 完成主机认证、操作者认证、加密与完整性保护，ctl 又在每个内部步骤重复签名、时间窗口、JTI、SHA、receipt 和 evidence。
- 官方制品已经由可信 Release metadata/attestation 绑定，代码又在缓存、阶段、运行时、回执和审计中反复证明同一事实。
- 外部数据库、Valkey、代理或证书 provider 已由对应平台负责，ctl 却要求 provider attestation、摘要矩阵和恢复 rehearsal 才允许继续。

本次目标是：**保留运营、治理、灾备和跨主机能力，但每个事实只在进入新的可信边界时验证一次；后续步骤继承该会话或已验证对象，不重复举证。**

### 2.1 ctl 的职责

1. 本机或通过 SSH 管理远端 NazoAuth 的安装、配置、启动、停止、状态、日志、更新、回滚和卸载。
2. 维护部署清单、具体资源 ownership、操作记录、健康状态和可选治理策略。
3. 管理本地回滚材料、可选备份、离机备份状态与恢复演练；准确报告灾备成熟度。
4. 通过本机一次性 NazoAuth 进程，或通过一个明确认证的远程 control transport，执行迁移、bootstrap、租户资源等应用级操作。
5. 可选运行 OIDF/OID4 一致性工作流并准备可复核材料。

### 2.2 不属于默认安全基线的事项

1. 不要求独立磁盘、独立文件系统、离机恢复包或恢复 rehearsal 才能安装、查看状态、诊断或更新。
2. 不要求本机/SSH 会话中的每一步再使用独立 controller、receipt、audit、break-glass 身份。
3. 不要求用户为外部 provider 提交 JSON evidence、receipt 或 attestation 才能继续本地操作。
4. 不维护 `external/delegated/managed × capability × scope` 的通用授权格。
5. 不用签名审计链声称能够抵御持有同一主机 root 的攻击者。
6. 不把公网 TLS、OIDC Discovery 或 UI 可达性作为本地安装事务提交的同步前置条件。
7. 不用多个 SHA、manifest digest 和 receipt digest 重复表达同一个不可变对象身份。
8. 不复制 NazoAuth 已有 Compose 开发沙箱，不引入第二个开发事实源。

## 3. 第一性原则：认证一次，边界处再验证

### 3.1 信任建立路径

本机路径：

```text
OS login / service account
  -> 文件权限、sudo/root 或 container-engine 权限
  -> 选择 deployment
  -> nazoauthctl 执行操作
```

SSH 跨主机路径：

```text
known_hosts / host certificate 验证远端主机
  -> SSH public-key / agent 验证操作者
  -> SSH 加密与 MAC 保护会话
  -> 远端 OS 用户 / sudo 决定权限
  -> 远端 nazoauthctl 执行操作
```

直接 HTTPS control path（只有确有消费者时保留）：

```text
TLS 验证服务端
  -> mTLS 或一套 controller credential 验证客户端
  -> server challenge / operation ID 防重放
  -> 受限 control operation
```

规则：同一次操作只能选择一种主认证路径。SSH 已认证时，不再叠加 ctl JWS；直接 HTTPS 已使用 mTLS/一套 controller key 时，不再要求 audit、receipt、break-glass 四套身份。

### 3.2 各类事实的验证次数

| 事实 | 何时验证 | 后续如何引用 | 禁止的重复证明 |
| --- | --- | --- | --- |
| 本机操作者 | 进程入口由 OS/sudo/runtime 权限决定 | 继承进程 credential | 每个子步骤再签 controller JWS |
| SSH 主机 | 建立或重连 SSH connection 时由 OpenSSH known_hosts/host cert 验证 | connection/session handle | ctl 再保存一份 host-key SHA 并逐步比较 |
| SSH 用户 | 建立或重连 connection 时由 OpenSSH key/agent 验证 | SSH session | 每个远端命令再发 actor evidence |
| 官方制品 | 在执行主机进入 verified cache 前验证 Release attestation、name、digest、size、compatibility | `VerifiedArtifact`/content-addressed handle | controller、本地 cache、远端 stage、activation receipt 各建一套 manifest-of-manifest |
| 本地制品 | 传入 ctl 时解析不可变 binary SHA 或 OCI digest；跨 SSH 传输后在执行主机确认一次 | immutable handle | 每阶段反复计算相同 digest |
| 运行中的制品 | activation 后观察一次 embedded identity 与期望 handle | runtime observation | 每个普通 status 都重放完整 Release attestation |
| 配置 | 写入时 schema 校验并分配单调 revision；变更用 CAS | config revision | 对 endpoint、principal、每个字段分别建 SHA 矩阵 |
| 操作幂等 | 创建 operation ID；副作用前后持久化阶段 | operation journal | JTI + iat + nbf + exp + request SHA 同时承担相同重放职责 |
| 外部 provider | 用户配置时校验 locator；需要时观察最终结果 | external resource reference | provider evidence/receipt 作为继续运行的强制材料 |
| 备份 | 备份完成时生成一个内容 manifest 并校验 restore 所需文件 | backup ID/manifest | manifest SHA 再放入 recovery manifest，再签 audit receipt |

### 3.3 时间使用规则

- 本机和 SSH 会话内的同步操作不使用跨主机 `iat/nbf/exp` 做身份认证。
- 超时使用进程或连接的 monotonic deadline，不依赖两台主机墙上时钟一致。
- 防重放使用 server challenge、operation ID 与持久化幂等记录，不用很窄的时间窗。
- 只有证书、OAuth/OIDC token、签名 Release metadata 的有效期等外部协议明确要求时间时才检查墙上时钟。
- `doctor` 可以报告 clock skew，但不得让与时间无关的 install/status/logs 因时钟偏差失败。

## 4. 威胁模型与最小控制

| 威胁 | 必须保留的控制 | 明确不要的过度控制 |
| --- | --- | --- |
| 中间人把远端主机替换 | OpenSSH host key/host certificate，禁止静默关闭 host-key checking | ctl 自己再实现一套远端主机 PKI |
| 未授权用户执行运营操作 | 本机 OS 权限；SSH public key + remote sudo；HTTPS path 的单一 credential | 本机会话内多身份连环签名 |
| 下载源/镜像被替换 | 一个权威 Release trust chain、digest、size、目标名与兼容性 | 同一制品多套 attestation 和 signed audit |
| 操作误落到错误部署 | 多目标歧义时显式 target；破坏性操作显示 host/deployment/resource 清单 | 每个资源单独 capability grant |
| 秘密泄露 | owner-only 文件/secret reference；禁止 argv、日志、诊断导出；最小远端传输 | 为 locator 构造 provider attestation 体系 |
| 崩溃造成半完成更新 | 小型原子 journal、幂等 resume/rollback、上一制品与配置 | 通用 coordination/evidence 状态机 |
| 重放应用级副作用 | operation ID + server-side result journal；HTTP path 用 challenge | 同时依赖 JTI、时间窗、request digest、receipt signature |
| 删除用户拥有的外部资源 | concrete resource `managed|external` ownership | capability × scope × delegated 权限格 |
| 备份损坏 | 一个 backup manifest、恢复时内容校验、可选演练 | 备份 manifest 的 manifest、provider receipt、审计签名链 |
| 整机丢失 | 可选离机加密备份和恢复演练；状态明确 | 普通安装强制独立 device，并把同机目录误称整机灾备 |
| root/SSH 管理员恶意 | 记录为可信计算基；可把日志导出到外部 WORM/SIEM | 同主机 audit key 声称不可抵赖 |
| 公网 issuer/TLS 配错 | 独立 public verify 保持 HTTPS、issuer 精确匹配 | 公网尚未配置就撤销本地健康安装 |

## 5. 目标架构

### 5.1 Deployment 与资源

用具体事实替换通用授权格：

```text
Deployment
  id
  host = local | ssh-profile
  issuer
  runtime { backend, object, ownership }
  artifact { source, immutable_id, embedded_identity, current, previous? }
  config { path, revision }
  postgres { ownership, secret_ref }
  valkey   { ownership, secret_ref }
  public_endpoint { mode, last_observation? }
  backup_policy?
  assurance_policy?
  active_operation?
```

- `ownership = managed|external` 只回答 ctl 能否创建、替换或删除该具体资源，不承担身份授权。
- `host=ssh-profile` 引用用户现有 OpenSSH 配置中的 host alias；known_hosts、host certificate、user key、ProxyJump 等由 OpenSSH 权威管理，ctl 不复制 SSH 配置和私钥。
- `assurance_policy` 是少量显式 opt-in 策略，不是通用 policy engine。初始只允许有真实消费者的项目，例如 `backup-before-update = off|warn|require(max_age)` 与 `public-verify = observe|require`。
- 默认策略必须允许普通单盘安装和无离机备份更新；加强策略由运营方显式启用。

### 5.2 操作状态机

```text
Prepared -> ArtifactReady -> ChangeApplied -> LocalVerified -> Committed
                                   |              |
                                   +-- rollback --+
```

- 每个 deployment 同时只有一个变更操作；只读命令不因变更锁而全部失效。
- journal 保存恢复所需的最少事实：operation ID、host、deployment、kind、当前阶段、期望/上一 artifact/config revision、最近错误。
- 外部 provider 步骤不进入 journal；ctl 只观察用户完成后的最终状态。
- 本地 `Committed` 与公网 `public=healthy|unhealthy|unknown` 分开；默认 public failure 不回滚本地安装。

### 5.3 本机与远程执行适配器

同一 use case 只能依赖一个 `ExecutionTarget` 接口：

```text
ExecutionTarget
  inspect
  stage_verified_artifact
  apply_config_revision
  runtime_action
  run_operator_request
  read_health
```

- `LocalTarget` 使用直接进程/容器/systemd API。
- `SshTarget` 使用系统 OpenSSH 客户端；固定远端 executable 和关闭 JSON stdin/stdout 协议，不拼接 shell 字符串。
- SSH connection 建立后，整个 operation 复用它；连接丢失时重连并重新由 OpenSSH 认证，然后以 operation ID resume。
- 默认禁止 agent forwarding；ctl 不复制、读取或上传用户 SSH 私钥。
- 远端 sudo 由用户 SSH/remote policy 决定。无非交互 sudo 时给出明确错误，不尝试绕过。

### 5.4 operator transport

- 本机或 SSH 路径：远端 ctl 在目标主机本地启动一次性 NazoAuth operator 进程；不再给该本地子进程叠加长期 controller/audit/break-glass 身份。
- 关闭 request 保留 schema、operation ID、deployment ID、artifact/runtime expectation、config revision、operation 与 bounded payload。
- NazoAuth 保存幂等结果，解决“副作用已发生但响应丢失”。result 绑定同一 operation ID 即可，不需要 receipt 私钥。
- 直接 HTTPS control path 若确有生产消费者，使用 mTLS 或一套 controller credential，加 server challenge 防重放；禁止再叠加 SSH、receipt、audit、break-glass 四身份。
- controller credential 丢失时，使用已有 SSH/local root 恢复和重新登记；不强制生成另一套同机 break-glass key。

### 5.5 治理、审计与灾备

治理能力保留，但从“每步授权门禁”改为“清单、策略、观察和报告”：

- inventory：host、deployment、版本、runtime、资源 ownership、健康和备份成熟度。
- policy：只有实际运营需求对应的少量显式 opt-in 策略；默认最小安全。
- audit：结构化 operation log，记录 operation ID、已认证 transport、host alias、remote user、target、动作、结果与错误。需要抗本机篡改时导出到外部 WORM/SIEM，而不是同主机签名。
- DR 状态分开报告：`local-rollback-ready`、`backup-ready`、`off-host-ready`、`restore-tested`。未达到较高层级是状态或显式策略结果，不是所有命令的全局门禁。
- backup/recovery 可以是 ctl 管理能力；只管理 ctl 创建的备份目标，使用一个 manifest 和可选加密，不要求 provider attestation。

## 6. 必留、简化、删除矩阵

| 当前机制 | 决策 | 新边界 |
| --- | --- | --- |
| GitHub Release attestation、artifact digest/size、embedded identity | 保留但去重 | 执行主机验证一次；activation 后只观察运行身份 |
| Release anti-downgrade | 简化保留 | 普通 update 防误降级；显式 rollback/allow-downgrade 可执行 |
| SSH host/user authentication | 作为跨主机权威信任 | 复用 OpenSSH config/known_hosts/agent，不复制私钥与 host SHA |
| controller/receipt/audit/break-glass 四身份 | 删除默认体系 | 仅直接 HTTPS path 可保留一套 controller credential |
| `iat/nbf/exp` 本地 operator 时间窗 | 删除 | operation ID、challenge、monotonic timeout |
| signed audit chain/management audit intent | 删除默认体系 | JSONL + 可选外部不可变日志 sink |
| 独立 break-glass root/device | 删除默认要求 | SSH/local root 是恢复入口；离机备份是 opt-in DR 层级 |
| lifecycle contract/recovery driver/rehearsal | 可选化并简化 | 仅配置恢复功能时存在；不阻断 install/status/update |
| 8 capability × responsibility × scope | 删除 | concrete ownership + 少量显式 policy |
| `delegated` responsibility | 删除 | ctl 管理或 external；外部自动化无需向 ctl证明委托 |
| provider evidence/coordination transaction | 删除 | 观察最终状态；外部系统拥有自己的记录 |
| config endpoint/principal SHA 矩阵 | 删除 | secret reference + config revision + 实际连接结果 |
| registry 入口全局 failure-domain 校验 | 删除 | 只在相关 backup/DR 命令评价 readiness |
| 所有命令入口 require root | 删除 | 下沉到真实特权步骤；只读和可访问 runtime 可 rootless |
| 公网 HTTPS/issuer 精确匹配 | 保留 | 独立 public verify/正式 OIDF；默认不阻断 local commit |
| direct TLS/ACME | 保留可选能力 | ctl 选择管理时生效，不要求 provider receipt |
| OIDF 远程 driver trust | 保留一个信任链 | 因其执行代码；不延伸为部署授权 |
| OIDF 截图/提交材料签名恢复链 | 删除 | 普通 run manifest 和文件校验和足够复核 |

## 7. 文件职责与行数硬边界

当前快照有 20 个生产 Rust 文件超过 600 行，其中 `src/tls/acme.rs` 2166 行、`src/tls.rs` 1950 行、`src/deployment.rs` 1318 行、`src/install/secrets.rs` 1273 行、`src/controller/deployment.rs` 1269 行、`src/controller/commands.rs` 1251 行、`src/coordination.rs` 1244 行。不得继续在这些大文件叠加例外。

| 目标模块 | 唯一职责 | 上限 |
| --- | --- | --- |
| `src/deployment/model.rs` | deployment、host、resource ownership 数据 | 350 行 |
| `src/deployment/store.rs` | 锁、目标选择、原子读写 | 400 行 |
| `src/deployment/migrate_v1.rs` | 一次性旧 schema 转换 | 400 行 |
| `src/execution/mod.rs` | `ExecutionTarget` 契约 | 200 行 |
| `src/execution/local.rs` | 本机执行适配器 | 450 行 |
| `src/execution/ssh.rs` | OpenSSH 进程、session、关闭远端协议 | 500 行 |
| `src/operation/journal.rs` | operation 状态机与恢复 | 350 行 |
| `src/operation/install.rs` | install 用例 | 500 行 |
| `src/operation/update.rs` | update 用例 | 500 行 |
| `src/operation/rollback.rs` | rollback 用例 | 350 行 |
| `src/artifact/official.rs` | 官方制品唯一信任验证 | 500 行 |
| `src/artifact/local.rs` | 本地制品不可变身份 | 300 行 |
| `src/operator/request.rs` | 最小 request/result | 300 行 |
| `src/operator/executor.rs` | 一次性 operator 进程与幂等结果 | 450 行 |
| `src/governance/inventory.rs` | 跨主机 inventory | 400 行 |
| `src/governance/policy.rs` | 少量已落地的 opt-in policy | 300 行 |
| `src/governance/audit.rs` | 普通 operation log 与外部 sink | 350 行 |
| `src/recovery/backup.rs` | 备份创建/校验 | 500 行 |
| `src/recovery/restore.rs` | 恢复与演练 | 500 行 |
| `src/tls/*` | external/direct/ACME 各自职责 | 每文件 500 行 |
| `src/oidf/*` | driver/run/export/browser/submission 分开 | 每文件 600 行 |
| `src/cli/*` | parser/help/output，不承载业务规则 | 每文件 500 行 |

规则：

- 完成后 NazoAuthCtl 所有手写生产 `.rs` 文件不超过 600 行，测试文件不超过 1000 行。
- NazoAuth 本次新增或修改的生产文件不超过 600 行；未触及的历史超限文件不得增长。
- 不创建 `common.rs`、`utils.rs`、`helpers.rs`、万能 controller 或只转发一次调用的 wrapper。
- 按状态所有权、用例和外部边界拆分；单一职责不等于一类型一文件。
- 删除旧实现后再接入新实现；只允许有明确删除版本的 schema/protocol migration adapter 暂时存在。
- 每个新 public API 必须列出真实生产消费者；无消费者即删除。
- 总生产 LOC 应净减少。净增加必须证明对应新的必要能力，不能以“为了以后”解释。

## 8. 执行前统一规则

每项任务开始前记录：

```powershell
git -C D:\self\NazoAuthCtl status --short --branch
git -C D:\self\NazoAuth status --short --branch
git -C D:\self\NazoAuthWeb status --short --branch
Get-PSDrive -Name D
Get-Process cargo,rustc,rustdoc -ErrorAction SilentlyContinue
```

- 存在非本任务修改时停止，不覆盖、不暂存、不顺手格式化。
- 开始全工作区、全特性、发布或覆盖率构建前，检查 D 盘空间、项目 target 实际大小、目录归属和运行中的构建进程；只清理当前工作区已失效且可重建的产物。
- NazoAuth 是 operator contract 权威源；先修改并验证 NazoAuth，再更新 NazoAuthCtl 的精确依赖，禁止复制 wire type。
- 每项任务结束运行 `git diff --check`、聚焦测试和 `git status --short`。
- 本计划不授权推送、合并、生产部署或发布 v0.2.0；实现代理只提交到负责人指定的唯一集成分支。

## 9. 任务清单

## [] T0 — 盘点重复证明，冻结真实信任边界

**目标**：在改代码前追完本机、SSH、直接 HTTPS、制品、配置、operator、backup 和 OIDF 调用链，明确每个校验是否保护了新边界。

**必读顺序**：

1. `D:\self\NazoAuthCtl\README.md`
2. `D:\self\NazoAuthCtl\docs\architecture.md`
3. `D:\self\NazoAuthCtl\docs\recovery.md`
4. `D:\self\NazoAuthCtl\docs\discovery-adoption.md`
5. `D:\self\NazoAuthCtl\src\controller.rs`、`src\deployment.rs`、`src\coordination.rs`
6. `D:\self\NazoAuthCtl\src\operator`、`src\tenant_resources.rs`、`src\runtime_backend`
7. `D:\self\NazoAuth\crates\authorization-server\src\operator_task`、`control_discovery.rs`
8. `D:\self\NazoAuth\crates\operator-protocol`

**执行内容**：

1. 在 `D:\self\NazoAuthCtl\docs\adr\0001-trust-once-at-boundary.md` 写出第 3 节三条信任路径和可信计算基。
2. 核实当前跨主机能力究竟是“外部 ssh 调用远端 ctl”、内部 SSH adapter、直接 HTTPS control，还是它们的组合；必须追到进程、socket、stdin/stdout 或 HTTP client。
3. 为每个现有校验建立 ledger：位置、输入事实、前一层是否已验证、保护的新边界、真实攻击者、失败代价、`keep/simplify/delete`。
4. 对每个 SHA 建 lineage，区分 artifact bytes、runtime observation、config revision、backup content、evidence file；表达同一事实的重复 SHA 必须合并。
5. 对每个 `iat/nbf/exp/JTI` 建用途表；能由 operation ID、challenge 或 monotonic timeout替代的全部标删除。
6. 对 controller、receipt、audit、break-glass 四类 identity 列出实际 verifier 与 transport。没有跨不可信边界 verifier 的 identity 标删除。
7. 记录三个仓库 exact SHA、工作树、生产/测试 LOC 和全部 >600 行文件。

**禁止**：不得以现有测试、文档或“安全最佳实践”证明控制必须存在；必须说明资产、攻击者和新信任边界。

**验收**：ledger 覆盖所有生产 `bail!` 门禁类别；明确哪些校验是边界校验、状态不变量、用户策略或纯重复；负责人审阅 ADR 后才能进入 T1。

**执行证据**：待填写。

## [] T1 — 建立统一 Local/SSH/HTTPS 执行边界

**目标**：让本机、SSH 和直接 HTTPS 各自只认证一次，所有用例依赖统一执行目标，不在业务层反复证明 transport 身份。

**主要文件**：新 `src/execution/*`、现有 runtime/process/controller 调用点、必要的 CLI host 选项。

**执行内容**：

1. 提取 `ExecutionTarget`，只暴露 inspect、stage、config、runtime、operator、health 六类必要操作；不得把 SSH 细节泄漏到 use case。
2. `LocalTarget` 复用当前 OS/process/runtime 权限，不创建 session key。
3. `SshTarget` 调用系统 OpenSSH，引用 host alias；继承 OpenSSH 的 known_hosts、host certificate、ProxyJump、user key/agent 和 sudo 配置。
4. 默认 `StrictHostKeyChecking` 不得被 ctl 关闭；host key 改变必须失败并把修复交给 OpenSSH 工具链。
5. 禁止默认 agent forwarding；不读取、不复制、不上传 SSH 私钥。
6. 使用固定远端 executable 和 JSON stdin/stdout，不拼接用户输入到 shell command。远端命令参数用独立 argv 或 stdin protocol。
7. 一个 operation 复用一个 SSH connection/session；每个内部阶段不得重新认证。断线后重连由 OpenSSH 重新认证，并使用 operation ID resume。
8. 如果保留直接 HTTPS target，只允许 mTLS 或一套 controller credential 二选一；challenge 防重放，不要求 SSH 与 HTTPS 凭据叠加。
9. audit 只记录 OpenSSH 已确认的 host alias/user/session 事实，不复制保存 host-key digest 作为第二权威源。

**测试**：local 成功、SSH host key mismatch、错误 user key、无 sudo、connection reuse、断线 resume、命令注入输入、agent forwarding 默认关闭、HTTPS credential/challenge、禁止双认证默认路径。

**验收**：业务 use case 不知道 SSH/JWS；同一 operation 只发生一次 transport authentication（重连除外）；跨主机仍可执行全部支持的生命周期操作。

**执行证据**：待填写。

## [] T2 — 收缩 operator contract，删除身份与时钟重复层

**目标**：应用级操作仍由 NazoAuth 执行并保持幂等，但不在 Local/SSH 已认证路径上再次运行四身份与窄时间窗体系。

**修改边界**：

- 权威源：`D:\self\NazoAuth\crates\operator-protocol`、`D:\self\NazoAuth\crates\authorization-server\src\operator_task`。
- 消费者：`D:\self\NazoAuthCtl\src\operator`、`tenant_resources.rs` 及直接调用者。

**执行内容**：

1. 为 Local/SSH target 定义关闭的 protocol v2 request/result：schema、operation ID、deployment ID、artifact/runtime expectation、config revision、operation、bounded payload、stable result/error。
2. 删除该路径的 JWS、controller/receipt/audit/break-glass key、actor evidence、key rotation、`iat/nbf/exp`。
3. NazoAuth 保留 server-side operation journal：相同 ID/相同请求返回原结果；相同 ID/不同请求拒绝；副作用后响应丢失不重复执行。
4. request 只走 stdin 或 owner-only 临时文件，不进 argv；result 是单个 stdout JSON，stderr 不含秘密。
5. direct HTTPS control path 若有实际消费者，收缩为一套 credential + server challenge + operation ID；可与 Local/SSH request 共享业务 payload，但认证 envelope 只存在于 HTTPS adapter。
6. controller credential 丢失的恢复入口是 SSH/local root 重新登记；audit 输出到普通/外部日志；不为默认部署再建 break-glass key。
7. v0.1.x -> v0.2.0 可保留一个独立 v1 migration adapter，只允许旧 runtime 升级使用，不双写、不用于 clean install，最晚 v0.3.0 删除。
8. 删除 ctl 的 audit verify/show、identity rotation、break-glass 公共命令中没有其他真实消费者的部分；若治理 UI 需要 audit view，改读结构化 operation log。

**测试**：绑定错误、operation 重放/冲突、各崩溃点、secret redaction、Local/SSH 无长期 key、HTTPS challenge replay、v1 adapter 只在迁移可达。

**验收**：clean install 在 Local/SSH 模式不生成四套身份；migrate/bootstrap/tenant-resource 仍正确；时钟偏差不影响 Local/SSH operator 操作。

**执行证据**：待填写。

## [] T3 — 合并 deployment、ownership 与配置 revision

**目标**：删除 capability 授权格和摘要矩阵，保留治理所需 inventory、资源 ownership 和少量 opt-in policy。

**主要文件**：`src/deployment.rs`、`src/model.rs`、`src/governance.rs`、`src/coordination.rs`、`src/adoption/*`、`src/install/config.rs`。

**执行内容**：

1. 实现第 5.1 节 Deployment schema，host 引用 Local/SSH profile，资源使用 `managed|external`。
2. 删除 `Capability`、`CapabilityGrant(s)`、`Responsibility`、`ResourceScope`、通用 `TrustState` 和所有 CLI/help/serialization 分支。
3. 删除 `delegated`：ctl 要么管理具体资源，要么把它视为 external；外部自动化无需证明委托关系。
4. 配置使用单调 revision + 原子 CAS；删除 endpoint/principal/backup URL 等逐字段 SHA 矩阵。secret 值仍只使用 reference。
5. 删除 registry 入口的 failure-domain、break-glass root 和不同 device 校验；这些只在 backup/DR readiness 中观察。
6. 将治理收缩为 inventory 和实际使用的 opt-in policy；删除 management audit intent、provider coordination/evidence。
7. 编写一次性旧 schema 迁移：`managed -> managed`，`external/delegated -> external`，无法证明 ctl 创建则 external；迁移前生成 owner-only 完整 backup，成功后不双写旧 schema。
8. 旧 identity/recovery/provider evidence 只留在 migration backup，不挂载、不读取；文档提供旧 binary/state 恢复步骤。

**测试**：单盘默认、v1 迁移/原子失败/重复执行、ownership 映射、config CAS、shared external 不删除、host profile roundtrip、旧 evidence 不再可达。

**验收**：新状态没有 capability grant、provider evidence、break-glass root 与字段 SHA 矩阵；inventory 和 opt-in policy 仍可跨主机汇总。

**执行证据**：待填写。

## [] T4 — 让制品只验证一次并使用不可变 handle

**目标**：保留供应链安全，消除同一制品在 controller、cache、stage、activation、receipt 中的重复举证。

**主要文件**：`src/release.rs`、`src/controller/self_update.rs`、安装脚本、Release workflows、新 `src/artifact/*`。

**执行内容**：

1. 官方制品在执行主机进入 cache 前，通过一个权威 Release trust chain 验证 repository/tag/workflow identity、predicate、name、digest、size 和 compatibility。
2. 调用方只能拿到 `VerifiedArtifact`；未验证 path 不得进入 runtime adapter。
3. LocalTarget 在本机验证；SshTarget 优先让远端下载并验证。若传输本地制品，远端接收完成时确认一次 immutable ID，随后存为 content-addressed/read-only object。
4. activation 后只观察 runtime embedded identity 与期望 handle，证明“运行的是目标制品”；不重放整个 GitHub attestation。
5. cache 命中只检查可变性边界：若内容存储可写，重新核对一次 digest；若由只读 content-addressed store 保证，可直接引用 handle。
6. self-update 复用相同验证原语与原子替换，删除 signed audit/management intent；保留当前二进制 target/owner/mode 安全检查。
7. anti-downgrade 只防普通 update 误操作；显式 rollback/`--allow-downgrade` 可执行并写 operation log，不要求 break-glass。
8. 本地 artifact 标记 `source=local`，不修改 official trust floor。

**测试**：错误 trust identity/size/digest、cache 篡改、远端 stage、activation identity mismatch、同版本身份变化、local 不污染 official floor、自更新原子失败恢复。

**验收**：每个制品的 trust verification 只有一个生产入口；列出的每个剩余 digest 都表达不同事实；不存在 manifest-of-manifest 链。

**执行证据**：待填写。

## [] T5 — 用小型 journal 重写 install/update/rollback/adopt

**目标**：本机和远端部署默认可用、可重试、可解释；高 assurance 由显式 policy 加强，不是硬编码全局门禁。

**主要文件**：`src/install.rs`、`src/controller/deployment.rs`、`src/controller/updates/*`、`src/discovery.rs`、`src/adoption/*`、新 `src/operation/*`。

**执行内容**：

1. 实现第 5.2 节五阶段 journal；每阶段幂等，只保存 resume/rollback 必要事实。
2. clean install 默认只需 target/runtime、public URL 和依赖；不要求 recovery root、backup root、provider evidence 或 rehearsal。
3. 权限检查下沉到真实 privileged step：systemd/system path/chown 需要 sudo；用户有 socket 权限的 Docker/Podman 可 rootless；status/logs/doctor/discover 不无条件要求 root。
4. local health 与 activation identity 成功即提交本地 install。公网观察单独记录；默认失败不撤销安装。显式 `public-verify=require` policy 才将其作为完成策略。
5. update 保留上一 artifact/config revision；本地 activation/health 失败自动回滚。数据库不可逆迁移边界由 Release contract 声明，ctl 不伪造数据回滚。
6. discover 无 registry/root/recovery 要求；adopt 只需唯一 target 和 plan 确认。runtime/artifact/config 按明确接管记 managed，外部依赖默认 external。
7. 删除 lifecycle/recovery evidence/provider attestation/capability flags/adoption signed receipt 默认路径。
8. operation 仅提供 `status|resume|abort`；abort 不协调外部 provider，只撤销未提交的 ctl-owned 本地/远端变更。

**测试**：普通单盘、rootless Docker/Podman、systemd 非 root、SSH remote install、public 未配置仍 local commit、每阶段 kill/resume、artifact rollback、adopt 无 evidence、external 零删除。

**验收**：README 最短路径在普通主机和 SSH 远端都成功；无用户 opt-in policy 时不被 backup/public/recovery 成熟度阻断。

**执行证据**：待填写。

## [] T6 — 保留治理能力，但从授权迷宫改为 inventory、policy 与外部审计

**目标**：ctl 继续承担运营治理，治理信息不再成为每个技术步骤重复认证的理由。

**主要文件**：新 `src/governance/*`、CLI inventory/policy/audit、旧 `governance.rs` 与 audit modules。

**执行内容**：

1. inventory 汇总 host、deployment、release、runtime、ownership、health、public observation、backup/restore maturity 和 active operation。
2. 初始 policy 只实现有真实消费者的：backup-before-update、public-verify、interactive destructive confirmation。不得实现通用表达式语言或任意 capability engine。
3. 所有加强策略默认 off 或 warn；`require` 必须由用户显式配置，并在阻断时指出 policy 名、配置位置、当前证据和解除方法。
4. audit 改为结构化 JSONL：operation ID、transport kind、host alias、OS/SSH principal、deployment、action、result、error、开始/结束时间。它用于运营复盘，不声称抗 root 篡改。
5. 支持可选外部 sink（stdout/file/syslog 中实际已有消费者者优先）；需要 WORM/SIEM 时依赖外部系统，不自建签名链。
6. 删除 controller audit key、audit verify chain、management audit intent；audit 写失败默认报告 warning，不回滚已经安全提交的操作。显式 `audit-required` policy 若确有消费者可在操作前检查 sink 可用性，但不得在提交后制造半完成。
7. 多主机 inventory 允许部分失败并列出每台 host 错误，不因一台时钟/备份/公网异常隐藏其他结果。

**测试**：默认 policy 不阻断、显式 require 正确阻断、policy 错误可操作、partial inventory、audit redaction、sink failure 语义、无 audit key clean install。

**验收**：治理能力可用且清晰；默认部署不需要理解 capability/audit identity；加强控制都是显式、可定位、可关闭的用户策略。

**执行证据**：待填写。

## [] T7 — 保留备份与灾备能力，但把成熟度从全局门禁变为分层状态

**目标**：ctl 能创建备份、验证、恢复、演练和报告离机状态，但普通生命周期不假装等于灾备验收。

**主要文件**：`src/backup.rs`、`src/lifecycle*`、`docs/recovery.md`、新 `src/recovery/*`。

**执行内容**：

1. 定义四个独立状态：local rollback、backup complete、off-host copy、restore tested；每个有自己的证据和更新时间。
2. 默认 install/update 只要求本地原子性。用户启用 `backup-before-update=require(max_age)` 后才检查相应 backup 状态。
3. 备份由一个 manifest 绑定必要文件、大小和内容 hash；使用加密存储时由 AEAD 提供完整性，不再叠加 recovery manifest/audit receipt。
4. off-host 只检查配置目标与最近一次成功传输；不把“不同本地 device”冒充 off-host。
5. restore rehearsal 是显式命令/策略；失败影响 `restore-tested` 状态，不让 status/logs/install 失效。
6. external PostgreSQL/Valkey 默认由外部平台备份，ctl 记录 reference/last observation；不要求 provider attestation。用户显式配置 adapter 时，adapter 使用固定 executable + argv/stdin，不通过 shell 拼接。
7. controller credential 丢失时使用 SSH/local root 恢复；如果直接 HTTPS credential 需要轮换，只轮换这一套，不创建同机 break-glass identity。
8. 删除全局 failure-domain validation、mandatory recovery driver、schema-2 evidence chain 和 adoption rehearsal gate。

**测试**：无 backup 正常默认 update、显式 require、backup manifest corruption、off-host 与同盘区分、restore rehearsal 失败状态、external adapter、SSH 主机恢复、无 break-glass device。

**验收**：ctl 的 DR 功能完整但分层如实；用户能选择高 assurance；默认单盘使用不被阻断。

**执行证据**：待填写。

## [] T8 — 简化 TLS、外部 provider 与 OIDF/OID4 辅助链

**目标**：保留协议正确性、可选证书管理和一致性套件能力，删除与真实边界无关的证据链。

**主要文件**：`src/tls.rs`、`src/tls/acme.rs`、TLS provider docs、`src/oidf*`、tenant resource 对接。

**执行内容**：

1. TLS 模式只表达 `external-proxy|direct-tls|acme|loopback`；不是 capability grant。
2. external proxy 只配置 issuer/trusted-proxy 并观察最终公网 endpoint；不要求 reload receipt/provider evidence。
3. direct TLS 验证 cert/key match、域名、权限与有效期；ACME 只管理自己创建的 account/challenge/cert，拆分到每文件不超过 500 行。
4. public verify 保留 HTTPS、issuer/Discovery 精确匹配；loopback 明确不是正式公网/OIDF 环境。默认 public failure 不回滚 local commit。
5. 远程可执行 OIDF driver 保留一个签名/摘要信任链与大小限制；本地显式 driver 标记 immutable local ID。
6. 删除截图、Browser Interaction、上传清单、retention manifest 的签名/恢复链；保留普通 run manifest：plan/module、server artifact、结果与文件名/hash。
7. Suite token/client secret 不进日志、manifest、错误与诊断包。
8. OID4 tenant resource 通过 T2 transport；保留 tenant、revision/CAS、change set 和 run-owned cleanup，删除无额外边界的 capability lease/evidence。
9. 一致性套件发现的协议缺陷必须按规范修 NazoAuth；不得为通过测试在 ctl 增加例外。

**测试**：external proxy 零 evidence、direct TLS、ACME ownership、公网 issuer mismatch、OID4 plan filter、driver 篡改、token redaction、run manifest 可复算、资源只清理本 run 所有。

**验收**：TLS/OIDF 能力完整但不影响 install/update/status 授权；正式协议安全要求未放宽。

**执行证据**：待填写。

## [] T9 — 重写 CLI/文档并删除旧实现

**目标**：默认路径只暴露 ctl 语境所需信息；代码中不留下新旧两套体系。

**执行内容**：

1. CLI 保留 install、discover、adopt、inventory、status、logs、doctor、verify、update、rollback、operation、policy、backup/recovery、OIDF、uninstall 和必要 operator 用例。
2. 删除 capability grant、provider evidence、management audit、四身份 rotation、mandatory lifecycle/rehearsal 等参数/help topic；不得保留 deprecated no-op。
3. 单一 deployment 可默认；零个或多个歧义时要求选择。破坏性多主机/多部署操作必须明确 host + deployment，并显示 managed deletion 清单。
4. 错误统一给出 operation、target、当前阶段、已发生副作用、下一条命令；时间/SHA 错误必须说明保护的真实对象，不能只输出“mismatch”。
5. README 第一屏展示本机、SSH 远端、外部代理、adopt、backup policy 五条最短路径；高级治理/DR 独立文档。
6. 用 `rg` 删除 `CapabilityGrant`、`delegated`、默认 `break_glass`、`audit_private_key`、`provider_attestation`、`management audit intent`、强制 `recovery_manifest` 等生产可达性。
7. 拆分所有 >600 行生产文件与 >1000 行测试文件；先删失效代码再拆，不做机械搬运。
8. 增加 CI line-limit 与依赖方向检查：CLI -> use case -> domain/store/adapter；domain 不依赖 CLI、SSH、GitHub、runtime backend 或 OIDF。
9. 对比前后生产 LOC、CLI 命令数、配置字段、默认长期私钥数、默认 install 必填参数与一次 operation 的验证次数。

**验收**：手写文件全部达标；旧体系生产可达性为零；无 utils/common 垃圾桶；生产 LOC 净减少；README 默认路径无需证据链知识。

**执行证据**：待填写。

## [] T10 — 全矩阵、CI 与交付审计

**构建前置**：检查磁盘、target 归属和 cargo/rustc 进程；记录实际空间与清理证据。

**本地命令**：

```powershell
cd D:\self\NazoAuth
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo build --locked --workspace --all-targets --all-features

cd D:\self\NazoAuthCtl
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo build --locked --workspace --all-targets --all-features
```

**必须完成的真实场景**：

1. 普通单盘 Linux，Docker clean install，无 backup/recovery/provider evidence。
2. Podman rootless clean install。
3. systemd 非 root 在真实特权步骤失败，sudo 后安全 resume。
4. `ssh host nazoauthctl ...` 或目标 SSH adapter：host key、user key、sudo、connection reuse、断线 resume。
5. 外部 PostgreSQL、Valkey、proxy；ctl 不删除三者。
6. 公网尚未配置：local commit 成功、public unhealthy；配置后 verify 成功。
7. 官方 update 与每个 journal 阶段 kill/resume/rollback。
8. local artifact activation 且 official trust floor 不变。
9. v0.1.x 状态/protocol 迁移，失败可恢复旧 binary/state。
10. operator replay/conflict/response-loss；Local/SSH 时钟偏差不阻断。
11. 多主机 inventory 部分失败；policy 默认不阻断、显式 require 正确阻断。
12. backup、off-host copy、restore rehearsal 四层状态；同盘不误报 off-host。
13. direct TLS、external proxy、ACME、loopback 与 issuer mismatch。
14. OID4 计划全流程；token 不泄露；run manifest 与文件一致。
15. uninstall 只删除 managed 资源。
16. NazoAuthWeb 保持无行为变化；若无修改，只记录现有 CI，不制造提交。

**CI 验收**：

- 三仓相应 exact-head required checks 全绿，不用旧 SHA 或可选 job 替代。
- 增加普通单盘、rootless、SSH remote、v1 migration、operation crash-recovery、policy default 和 line-limit jobs。
- compatibility workflow 继续验证官方 server artifact 与 operator protocol 精确兼容。

**交付报告**：每仓 SHA/diffstat/删除文件、LOC 前后、命令与退出码、CI URL/exact head、场景原始证据、未验证边界、migration rollback、v1 adapter 删除版本。

**完成条件**：T0-T9 全为 `[ x ]`，本地/真实运行/CI 证据全部具备且无 blocker，才能将 T10 标记 `[ x ]`。完成不等于已合并、部署或发布 v0.2.0。

**执行证据**：待填写。

## 10. 停止规则

遇到以下情况必须停止当前任务并报告：

1. 发现未记录的跨主机 transport 或非 SSH/HTTPS 的生产调用者。
2. 删除某 identity 会让不持有 OS/SSH/HTTPS credential 的合法调用者失去唯一认证边界。
3. 某个 SHA 实际表达不同安全事实，不能安全合并。
4. 旧 schema 无法无损映射 host、deployment、artifact、secret reference 或 resource ownership。
5. 数据库 migration 的回滚兼容性没有 Release contract。
6. 需要修改 OIDC/OAuth/OID4 行为才能让 ctl 测试通过；必须另立规范任务。
7. 存在用户未提交修改、未知 worktree 或并行构建使用相同 target。
8. 默认路径只能在独立 device/tmpfs、特制时钟或预制 evidence 下通过。
9. 为保持旧测试需要重新引入已判定重复的身份、时间、SHA 或 evidence 层。

## 11. 规范与工程依据

- [OpenSSH ssh(1) — host verification and public-key authentication](https://man.openbsd.org/ssh)
- [OpenSSH sshd(8) — encrypted, integrity-protected and authenticated session](https://man.openbsd.org/sshd)
- [OpenSSH ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
- [NIST SP 800-53 Rev. 5, CM-7 Least Functionality](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)
- [The Update Framework Specification](https://theupdateframework.io/specification/latest/)
- [NIST Security Considerations for Code Signing](https://csrc.nist.gov/pubs/cswp/5/security-considerations-for-code-signing/final)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)

这些资料不是要求把所有控制叠加起来的清单。对本项目而言，保留控制的充分条件是：它保护 ctl 职责内的资产、面对明确攻击者、位于新的可信边界，并且没有被 OS、SSH、TLS 或已验证 immutable handle 等上一层可靠机制完整覆盖。
