//! 出站流生命周期通用驱动器（模板方法模式）
//!
//! 统一接管所有出站协议（Claude、OpenAI 等）的通用流式生命周期：
//! 1. 3s 细粒度保活心跳（`: ping\n\n`）；
//! 2. 45s 空闲静默快速熔断（`IDLE_TIMEOUT_SECS = 45`）；
//! 3. 网络中断统一拦截与状态判断（`has_content` / `has_thinking`）；
//! 4. 协议守卫（首包报错后严禁追加终结帧）；
//! 5. 尾部数据安全 Flush（修复 #1732）。
//!
//! 各协议发散层适配器仅实现 `ProtocolStreamHandler` 专有渲染 Trait。

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use std::pin::Pin;

use crate::proxy::mappers::error_classifier::StreamErrorReport;

/// 出站协议特定帧渲染 Trait
pub trait ProtocolStreamHandler: Send + 'static {
    /// 可选：在流开始前发送的初始握手帧（例如 Codex 的 response.created）
    fn initial_frames(&mut self) -> Vec<Bytes> {
        Vec::new()
    }

    /// 处理上游 SSE 的单行数据（例如 "data: {...}"）
    /// 返回需要向下游发送的字节块序列
    fn process_line(&mut self, line: &str) -> Vec<Bytes>;

    /// 检查是否已有正文内容输出给下游（用于判断中断时是优雅截断还是首包不可重试错误）
    fn has_content(&self) -> bool;

    /// 可选：检查是否已有思考内容输出（例如 Claude 的 thinking 块，用于后思考恢复通道）
    fn has_thinking(&self) -> bool {
        false
    }

    /// 当流被中断或超时且 has_content() == true 时调用
    /// 注入协议专属的截断提示（Claude 下发 text_delta，OpenAI 可选下发 delta 或平稳截断）
    fn emit_interruption_truncation(&mut self) -> Vec<Bytes> {
        Vec::new()
    }

    /// 流正常结束或截断恢复后调用，产出协议专属的终结帧
    /// （Claude 下发 message_delta(end_turn) + message_stop，OpenAI 下发 [DONE] 及可选 usage chunk）
    fn emit_finalize(&mut self) -> Vec<Bytes>;

    /// 首包发生致命错误/超时且 has_content() == false && has_thinking() == false 时调用
    /// 返回协议专属的非重试终端错误帧（Claude 下发 api_error，OpenAI 下发 error frame）
    fn emit_initial_error(&mut self, error_report: &StreamErrorReport) -> Vec<Bytes>;

    /// 可选钩子：心跳帧自定义渲染（缺省为标准 SSE 注释 `: ping\n\n`）
    fn heartbeat_frame(&mut self) -> Bytes {
        Bytes::from(": ping\n\n")
    }

    /// 可选钩子：流终止前提交会话状态（如 thinking_acc.commit(session_id)）
    fn on_finish(&mut self) {}
}

/// 流生命周期通用配置
#[derive(Debug, Clone)]
pub struct StreamLifecycleConfig {
    pub heartbeat_secs: u64,
    pub idle_timeout_secs: u64,
    pub adapter_name: &'static str,
    pub function_name: &'static str,
    pub trace_info: String,
}

impl StreamLifecycleConfig {
    pub fn new(
        adapter_name: &'static str,
        function_name: &'static str,
        trace_info: String,
    ) -> Self {
        Self {
            heartbeat_secs: 3,
            idle_timeout_secs: 45,
            adapter_name,
            function_name,
            trace_info,
        }
    }
}

/// 通用出站流生命周期驱动器（模板方法）
pub fn run_stream_lifecycle<S, E, H>(
    mut upstream_stream: Pin<Box<S>>,
    mut handler: H,
    config: StreamLifecycleConfig,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>>
where
    S: Stream<Item = Result<Bytes, E>> + Send + ?Sized + 'static,
    E: std::fmt::Display + Send + 'static,
    H: ProtocolStreamHandler,
{
    use async_stream::stream;

    Box::pin(stream! {
        // 1. 发送可选的初始握手帧
        for frame in handler.initial_frames() {
            yield Ok(frame);
        }

        let mut buffer = BytesMut::new();
        let mut heartbeat_interval =
            tokio::time::interval(std::time::Duration::from_secs(config.heartbeat_secs));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_activity = tokio::time::Instant::now();
        let idle_timeout = std::time::Duration::from_secs(config.idle_timeout_secs);
        let mut error_emitted = false;
        let mut was_interrupted = false;

        loop {
            tokio::select! {
                next_chunk = upstream_stream.next() => {
                    match next_chunk {
                        Some(chunk_result) => {
                            last_activity = tokio::time::Instant::now();
                            match chunk_result {
                                Ok(chunk) => {
                                    buffer.extend_from_slice(&chunk);
                                    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                        let line_raw = buffer.split_to(pos + 1);
                                        let line_str = String::from_utf8_lossy(&line_raw);
                                        let line = line_str.trim();
                                        if line.is_empty() {
                                            continue;
                                        }

                                        let chunks = handler.process_line(line);
                                        for out_chunk in chunks {
                                            yield Ok(out_chunk);
                                        }
                                    }
                                }
                                Err(e) => {
                                    let report = crate::proxy::mappers::error_classifier::report_stream_error(
                                        config.adapter_name,
                                        config.function_name,
                                        &e,
                                        config.trace_info.clone(),
                                    );
                                    tracing::warn!(
                                        "[{}] {} upstream stream chunk error: {}",
                                        config.adapter_name,
                                        config.function_name,
                                        report.client_message()
                                    );

                                    // [优雅截断恢复与重试风暴切断]
                                    // 若正文或思考已经输出，绝不抛出可重试错误导致客户端指数退避卡死，
                                    // 而是平稳标记中断并跳出循环以完成正常收尾。
                                    if handler.has_content() || handler.has_thinking() {
                                        tracing::info!(
                                            "[{}] Stream interrupted after content/thinking emitted. Gracefully completing turn to prevent retry deadlock.",
                                            config.adapter_name
                                        );
                                        was_interrupted = true;
                                        break;
                                    } else {
                                        let err_chunks = handler.emit_initial_error(&report);
                                        for c in err_chunks {
                                            yield Ok(c);
                                        }
                                        error_emitted = true;
                                        break;
                                    }
                                }
                            }
                        }
                        None => break, // 上游流正常到达 EOF
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if last_activity.elapsed() >= idle_timeout {
                        let report = crate::proxy::mappers::error_classifier::report_stream_error(
                            config.adapter_name,
                            config.function_name,
                            &"stream idle timeout",
                            format!("{} idle_secs={}", config.trace_info, config.idle_timeout_secs),
                        );
                        tracing::warn!(
                            "[{}] {} stream idle timeout after {}s",
                            config.adapter_name,
                            config.function_name,
                            config.idle_timeout_secs
                        );

                        if handler.has_content() || handler.has_thinking() {
                            tracing::info!(
                                "[{}] Idle timeout after content/thinking emitted. Gracefully completing turn to prevent retry deadlock.",
                                config.adapter_name
                            );
                            was_interrupted = true;
                            break;
                        } else {
                            let err_chunks = handler.emit_initial_error(&report);
                            for c in err_chunks {
                                yield Ok(c);
                            }
                            error_emitted = true;
                            break;
                        }
                    }
                    yield Ok(handler.heartbeat_frame());
                }
            }
        }

        // 协议守卫：如果已经下发了初始错误帧，严格禁止追加发送终结帧，防止破坏客户端状态机
        if error_emitted {
            handler.on_finish();
            return;
        }

        // [FIX #1732] 尾部数据安全 Flush：防止因末尾缺少换行符产生网络分片悬挂
        if !buffer.is_empty() {
            let line_str = String::from_utf8_lossy(&buffer);
            let line = line_str.trim();
            if !line.is_empty() {
                let chunks = handler.process_line(line);
                for out_chunk in chunks {
                    yield Ok(out_chunk);
                }
            }
            buffer.clear();
        }

        // 中断场景下注入截断提示
        if was_interrupted {
            let trunc_chunks = handler.emit_interruption_truncation();
            for c in trunc_chunks {
                yield Ok(c);
            }
        }

        // 正常收尾或截断后收尾
        let final_chunks = handler.emit_finalize();
        for c in final_chunks {
            yield Ok(c);
        }

        handler.on_finish();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHandler {
        processed_lines: Vec<String>,
        has_content: bool,
        has_thinking: bool,
        finalized: bool,
        initial_error_emitted: bool,
        interrupted: bool,
    }

    impl MockHandler {
        fn new(has_content: bool, has_thinking: bool) -> Self {
            Self {
                processed_lines: Vec::new(),
                has_content,
                has_thinking,
                finalized: false,
                initial_error_emitted: false,
                interrupted: false,
            }
        }
    }

    impl ProtocolStreamHandler for MockHandler {
        fn process_line(&mut self, line: &str) -> Vec<Bytes> {
            self.processed_lines.push(line.to_string());
            self.has_content = true;
            vec![Bytes::from(format!("processed:{}\n", line))]
        }

        fn has_content(&self) -> bool {
            self.has_content
        }

        fn has_thinking(&self) -> bool {
            self.has_thinking
        }

        fn emit_interruption_truncation(&mut self) -> Vec<Bytes> {
            self.interrupted = true;
            vec![Bytes::from("[truncated]\n")]
        }

        fn emit_finalize(&mut self) -> Vec<Bytes> {
            self.finalized = true;
            vec![Bytes::from("[finalized]\n")]
        }

        fn emit_initial_error(&mut self, _report: &StreamErrorReport) -> Vec<Bytes> {
            self.initial_error_emitted = true;
            vec![Bytes::from("[initial_error]\n")]
        }
    }

    #[tokio::test]
    async fn test_lifecycle_normal_flow_and_flush() {
        let mock_stream = async_stream::stream! {
            yield Ok::<_, String>(Bytes::from("data: hello\n"));
            yield Ok::<_, String>(Bytes::from("data: world_without_newline"));
        };

        let handler = MockHandler::new(false, false);
        let config = StreamLifecycleConfig::new("test", "test_fn", "trace_1".to_string());
        let mut stream = run_stream_lifecycle(Box::pin(mock_stream), handler, config);

        let mut output = Vec::new();
        while let Some(item) = stream.next().await {
            if let Ok(b) = item {
                output.push(String::from_utf8_lossy(&b).to_string());
            }
        }

        let full_output = output.join("");
        assert!(full_output.contains("processed:data: hello"));
        assert!(full_output.contains("processed:data: world_without_newline"));
        assert!(full_output.contains("[finalized]"));
        assert!(!full_output.contains("[initial_error]"));
    }

    #[tokio::test]
    async fn test_lifecycle_initial_error_stops_without_finalize() {
        let mock_stream = async_stream::stream! {
            yield Err::<Bytes, _>("connection failed before any data".to_string());
        };

        let handler = MockHandler::new(false, false);
        let config = StreamLifecycleConfig::new("test", "test_fn", "trace_2".to_string());
        let mut stream = run_stream_lifecycle(Box::pin(mock_stream), handler, config);

        let mut output = Vec::new();
        while let Some(item) = stream.next().await {
            if let Ok(b) = item {
                output.push(String::from_utf8_lossy(&b).to_string());
            }
        }

        let full_output = output.join("");
        assert!(full_output.contains("[initial_error]"));
        assert!(
            !full_output.contains("[finalized]"),
            "Must NOT finalize after initial error"
        );
    }

    #[tokio::test]
    async fn test_lifecycle_interruption_after_content_gracefully_finalizes() {
        let mock_stream = async_stream::stream! {
            yield Ok::<_, String>(Bytes::from("data: partial content\n"));
            yield Err::<Bytes, _>("connection reset mid stream".to_string());
        };

        let handler = MockHandler::new(false, false);
        let config = StreamLifecycleConfig::new("test", "test_fn", "trace_3".to_string());
        let mut stream = run_stream_lifecycle(Box::pin(mock_stream), handler, config);

        let mut output = Vec::new();
        while let Some(item) = stream.next().await {
            if let Ok(b) = item {
                output.push(String::from_utf8_lossy(&b).to_string());
            }
        }

        let full_output = output.join("");
        assert!(full_output.contains("processed:data: partial content"));
        assert!(full_output.contains("[truncated]"));
        assert!(full_output.contains("[finalized]"));
        assert!(
            !full_output.contains("[initial_error]"),
            "Must NOT emit initial error when content exists"
        );
    }
}
