# Antigravity Tools v4.9.2-beta.2 全方位多智能体对抗审计报告

## 概述
本报告为多智能体对抗性代码审查（Workflow ID: `wf_29636c0a-450`，覆盖 8 大核心子系统、42 轮 1 对 1 极端对抗验证）的完整交付物。
经严密实机与代码溯源求证，共**确诊 23 项真实缺陷**（2 项 CRITICAL、12 项 HIGH、6 项 MEDIUM、3 项 LOW），并**成功辟除 19 项虚假警报**。

---

## 一、23 项已确诊真实缺陷汇总

| 编号 | 严重度 | 子系统 | 文件与位置 | 缺陷简述 |
|---|---|---|---|---|
| 1 | **CRITICAL** | `token_manager` | `src-tauri/src/proxy/token_manager.rs:480-496` | `invalid_grant` 异常分支中，持有 DashMap 分片写锁跨越 `disable_account.await` 并在同线程调用 `remove()` 触发自死锁 |
| 2 | **CRITICAL** | `client_isolation` | `src-tauri/src/modules/process.rs:1354-1385` | `get_process_info` 取 `argv[0]` 代替 `process.exe()`，导致 IDE 实例被误识别为经典版 |
| 3 | **HIGH** | `client_isolation` | `src-tauri/src/modules/process.rs:1389-1393` | macOS `.app` 目录切片采用跨字符串字节偏移，非 ASCII 或含参路径直接触发 Panic |
| 4 | **HIGH** | `client_isolation` | `src-tauri/src/modules/device.rs:98-110, 233, 312-332` | `write_profile` 与 `sync_service_machine_id` 硬编码经典版路径，切换 IDE 账号时污染经典版 `state.vscdb` |
| 5 | **HIGH** | `cowork_lifecycle` | `src-tauri/src/proxy/handlers/claude.rs:965-989` | 30s 免死租约过期后回退至弱特征匹配，第一条消息历史标记使会话永久免除压缩，抵消 Fix #3563 |
| 6 | **HIGH** | `cowork_lifecycle` | `src-tauri/src/proxy/handlers/claude.rs:1079-1085` | 静态条件 `num_msgs < 50` 误导致压缩提前终止并返回虚假 200 OK，后续交互报 400 |
| 7 | **HIGH** | `cowork_lifecycle` | `src-tauri/src/proxy/handlers/claude.rs:117-140` | `calculate_claude_fixed_overhead` 工具开销漏算描述和 schema，导致 `target_limit` 出现负间隙而死锁 |
| 8 | **HIGH** | `cowork_lifecycle` | `src-tauri/src/commands/patch.rs:751-801` | macOS 补丁注入过程中签名失败缺少回滚，导致原版二进制被未签名文件破坏，被 AMFI SIGKILL(137) 杀死 |
| 9 | **HIGH** | `cowork_lifecycle` | `src-tauri/src/commands/patch.rs:815-840` | 还原补丁流程中对官方签名备份执行 Ad-Hoc 重新签名，剥离官方开发者证书与 Keychain 授权 |
| 10 | **HIGH** | `inbound_pipeline` | `src-tauri/src/proxy/pipeline/inbound.rs:1263-1265, 1293` | 目标模型为空或官方非 Gemini 占位符时 Gatekeeper 被绕过，无签名 functionCall 穿透引发 Google 400 |
| 11 | **HIGH** | `token_manager` | `src-tauri/src/proxy/token_manager.rs:543-555` | 刷新锁竞争：`resolve_project_id_with_timeout` 复用 `refresh_locks`，被 10s 后台刷新阻塞误触 3.5s 超时 |
| 12 | **HIGH** | `sqlite_and_sandbox` | `src-tauri/src/modules/proxy_db.rs:1546-1584` | `proxy_logs.db` 混部未限额的 `tool_signatures` 表导致日志磁盘配额饥饿，热路径频繁触发 VACUUM |
| 13 | **HIGH** | `claude_request_mapper` | `src-tauri/src/proxy/mappers/claude/request.rs:3425-3436` | `test_foreign_claude_signature_dropped_for_gemini` 断言与生产环境丢弃历史思维规范冲突导致单测 Panic |
| 14 | **HIGH** | `claude_request_mapper` | `src-tauri/src/proxy/mappers/claude/request.rs:3231, 3328` | Gemini 历史思维修剪导致 `test_thinking_block_preserved_with_empty_signature` 单测失败 |
| 15 | **HIGH** | `schema_and_model_mapping` | `src-tauri/src/proxy/common/model_mapping.rs:270-294` | Claude 8 位快照日期（如 `20241022`）被当成版本号，导致老旧 3.5 快照模型泄漏进列表 |
| 16 | **MEDIUM** | `token_manager` | `src-tauri/src/proxy/token_manager.rs:595-616` | `resolve_project_id_with_timeout` 缺少负缓存，未绑项目的账号每次请求持续承受 3.5s 延迟惩罚 |
| 17 | **MEDIUM** | `schema_and_model_mapping` | `src-tauri/src/proxy/common/model_mapping.rs:351-360` | `ver_str.parse::<f32>()` 将 `3.10` 解析为 `3.1`，误淘汰 `gemini-3.10-flash` |
| 18 | **MEDIUM** | `inbound_pipeline` | `src-tauri/src/proxy/pipeline/inbound.rs:1684-1732` | 外层 `requestId` 重新生成 UUID 与内层 `labels.trajectory_id` 脱节，破坏分布式链路追踪 |
| 19 | **MEDIUM** | `cowork_lifecycle` | `src-tauri/src/proxy/handlers/claude.rs:863-870` | 压缩总结请求与正常对话轮次 Session Key 计算不一致，导致租约与手动压缩状态未命中 |
| 20 | **MEDIUM** | `schema_and_model_mapping` | `src-tauri/src/proxy/common/json_schema.rs:230-244` | 非对象类型的 `properties`（如 `null`）跳过清洗未规范化为 `{}`，Google Protobuf 报错 400 |
| 21 | **MEDIUM** | `cowork_lifecycle` | `src-tauri/src/proxy/handlers/claude.rs:58-60, 1139-1147` | `COWORK_MANUAL_COMPACT_SESSIONS` 无全局容量上限与定期清理，存在无界内存泄漏 |
| 22 | **LOW** | `claude_request_mapper` | `src-tauri/src/proxy/mappers/claude/request.rs:2441, 3510` | 历史思维块占位清洗导致单测预期脱节 |
| 23 | **LOW** | `token_manager` | `src-tauri/src/proxy/token_manager.rs:705-723` | `remove_account` 时漏删 `refresh_locks` 与 `invalid_grant_failures` 键 |

---

## 二、19 项经对抗验证辟除的“虚假警报”（False Positives）

1. `has_available_account` 跨 await 持锁：死代码（调用方为 0），无生产影响。
2. 单账号 429 遇到 `allow_grace = false` 发生 50ms 闪电空转：PR #3584 传入的真实号池大小与固定退避已彻底解决。
3. Google AIP-193 关键字缺失造成错误分类：Google 官方 REST/gRPC API 错误规范保证在配额耗尽时必返回标准大写 `RESOURCE_EXHAUSTED`。
4. `save_tool_signature` 未加 `LOG_WRITE_LOCK` 引发 SQLite 冲突：WAL 模式配置了 5000ms Busy Timeout，高并发由内核平滑排队。
5. 单测沙盒 `DATA_DIR_OVERRIDE` 环境变量跨用例泄漏：修改该变量的单测均受 `SHARED_TEST_ENV_LOCK` 保护且 RAII 还原。
6. macOS 补丁修补剥离 Hardened Runtime 签名：Apple Silicon 对篡改二进制必须 Ad-Hoc 重新签名才能被内核加载，属系统底线要求。
7. `transform_claude_request_in` 绕过思维块清洗：入站第一站 `InboundThinkingPipeline` 已集中消毒，内部无需重复。
8. 深度嵌套 JSON Schema 导致网关在 Debug 模式下断言 Panic：`debug_assert!` 在 Release 发布构建中被编译器剥离。
9. Round 2 延迟轮换在号池大于等于 7 时引发零等待：退避算法具备最小 1000ms 强制下限。
10. `close_tool_loop_for_thinking` 合成消息击垮上游 KV Cache：仅在工具调用链中断的极限恢复下触发，属可用性兜底。
11. Tools 为空时遗留孤立 `tool_config` 导致上游 400：管线末端空配置修剪器已彻底剥离。
12. `build_contents` 提前降级思维块覆盖重排逻辑：降级与重排属于正交阶段。
13. 经典版在未安装时隐式回退至 IDE 路径：在 PR #3584 中已彻底斩断。
14. Gatekeeper 未将下划线风格思维签名归一化：网关接收时已有双向驼峰兼容转换。
15. 单测套件缺少边界用例覆盖：现有 17 项重试单测已完全覆盖各种极端状态机。
16. `thinkingConfig` 懒提取泄漏未识别根字段：字段提取采用移动语义剥离，最终 Payload 无残留。
17. Gatekeeper 在低于 3.0 的 Gemini 模型上注入哨兵签名：网关仅对 3.5+ 模型生效。
18. Windows 环境下无命令行参数导致 IDE 排除失效：`process.exe()` 在 Windows 下始终返回非空绝对路径。
19. 工具链中断恢复丢弃 Assistant 消息：状态机恢复逻辑完整保留了工具执行上下文。
