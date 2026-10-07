// Claude mapper 模块
// 负责 Claude ↔ Gemini 协议转换

pub mod collector;
pub mod models;
pub mod request;
pub mod response;
pub mod streaming;
pub mod thinking_utils;
pub mod utils;

use crate::proxy::common::client_adapter::ClientAdapter;
pub use collector::collect_stream_to_json;
pub use models::*;
pub use request::{
    clean_cache_control_from_messages, merge_consecutive_messages, transform_claude_request_in,
    transform_claude_request_in_timed,
};
pub use response::transform_response;
pub use streaming::{PartProcessor, StreamingState};
pub use thinking_utils::filter_invalid_thinking_blocks_with_family; // [NEW]

use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;

/// 创建从 Gemini SSE 流到 Claude SSE 流的转换
pub fn create_claude_sse_stream<S, E>(
    mut gemini_stream: Pin<Box<S>>,
    trace_id: String,
    email: String,
    session_id: Option<String>, // [NEW v3.3.17] Session ID for signature caching
    scaling_enabled: bool,      // [NEW] Flag for context usage scaling
    context_limit: u32,
    estimated_prompt_tokens: Option<u32>, // [FIX] Estimated tokens for calibrator learning
    message_count: usize,                 // [NEW v4.0.0] Message count for rewind detection
    client_adapter: Option<std::sync::Arc<dyn ClientAdapter>>, // [NEW] Adapter reference
    registered_tool_names: Vec<String>,   // [FIX #MCP] Tool names for fuzzy matching
) -> Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>>
where
    S: Stream<Item = Result<Bytes, E>> + Send + ?Sized + 'static,
    E: std::fmt::Display + Send + 'static,
{
    use async_stream::stream;
    use bytes::BytesMut;
    use futures::StreamExt;

    Box::pin(stream! {
        let mut state = StreamingState::new();
        state.session_id = session_id; // Set session ID for signature caching
        state.message_count = message_count; // [NEW v4.0.0] Set message count
        state.scaling_enabled = scaling_enabled; // Set scaling enabled flag
        state.context_limit = context_limit;
        state.estimated_prompt_tokens = estimated_prompt_tokens; // [FIX] Pass estimated tokens
        state.set_client_adapter(client_adapter); // [NEW] Set adapter
        state.set_registered_tool_names(registered_tool_names); // [FIX #MCP] Set tool names
        let mut buffer = BytesMut::new();
        // [FIX #3621] 3s fine-grained downstream SSE heartbeat aligned with PR #3578.
        // Replaces coarse 20s timeout loop and prevents intermediate proxy/socket timeouts.
        let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(3));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut last_activity = tokio::time::Instant::now();
        // [FIX #3621] Reduced from 100s (5 pings * 20s) to 45s fail-fast.
        // Provides ample time for deep thinking models to output first token
        // while preventing 100s visual freeze on upstream stall.
        const IDLE_TIMEOUT_SECS: u64 = 45;
        let mut was_interrupted = false;
        let mut error_emitted = false;

        loop {
            tokio::select! {
                next_chunk = gemini_stream.next() => {
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
                                        if line.is_empty() { continue; }

                                        if let Some(sse_chunks) = process_sse_line(line, &mut state, &trace_id, &email) {
                                            for sse_chunk in sse_chunks {
                                                yield Ok(sse_chunk);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    let session = state
                                        .session_id
                                        .clone()
                                        .unwrap_or_else(|| "-".to_string());
                                    let report = crate::proxy::mappers::error_classifier::report_stream_error(
                                        "claude",
                                        "create_claude_sse_stream",
                                        &e,
                                        format!(
                                            "trace={} session={} messages={} buffer_bytes={}",
                                            trace_id,
                                            session,
                                            message_count,
                                            buffer.len()
                                        ),
                                    );
                                    tracing::warn!(
                                        "[{}] Claude SSE upstream stream chunk error: {}",
                                        trace_id, report.client_message()
                                    );

                                    // [FIX #3621] Interruption Recovery & Exponential Backoff Deadlock Cutoff:
                                    // If content or thinking has already started, DO NOT emit overloaded_error.
                                    // Emitting overloaded_error causes Anthropic SDK / Claude Code CLI to enter
                                    // an exponential backoff retry loop (5 retries * 100s = 20+ minutes freeze).
                                    // Instead, gracefully break out to finalize the message turn with end_turn.
                                    if state.has_content {
                                        tracing::info!(
                                            "[{}] Stream interrupted after content emitted. Gracefully completing turn to prevent retry deadlock.",
                                            trace_id
                                        );
                                        was_interrupted = true;
                                        break;
                                    } else if state.has_thinking {
                                        tracing::info!(
                                            "[{}] Stream interrupted after thinking emitted. Forwarding to thinking recovery.",
                                            trace_id
                                        );
                                        was_interrupted = true;
                                        break;
                                    } else {
                                        // No content and no thinking emitted yet:
                                        // Return standard Anthropic api_error (500) instead of overloaded_error (529),
                                        // and terminate immediately without sending trailing message_stop.
                                        let error_json = serde_json::json!({
                                            "type": "error",
                                            "error": {
                                                "type": "api_error",
                                                "message": report.client_message(),
                                                "function": report.function,
                                                "call_site": report.call_site(),
                                                "params": report.params,
                                            }
                                        });
                                        yield Ok(state.emit("error", error_json));
                                        error_emitted = true;
                                        break;
                                    }
                                }
                            }
                        }
                        None => break, // Stream 正常结束
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if last_activity.elapsed() >= std::time::Duration::from_secs(IDLE_TIMEOUT_SECS) {
                        let session = state
                            .session_id
                            .clone()
                            .unwrap_or_else(|| "-".to_string());
                        let report = crate::proxy::mappers::error_classifier::report_stream_error(
                            "claude",
                            "create_claude_sse_stream",
                            &"stream idle timeout",
                            format!(
                                "trace={} session={} messages={} idle_secs={}",
                                trace_id,
                                session,
                                message_count,
                                IDLE_TIMEOUT_SECS
                            ),
                        );
                        tracing::warn!(
                            "[{}] Claude SSE stream idle timeout after {}s",
                            trace_id, IDLE_TIMEOUT_SECS
                        );

                        if state.has_content {
                            tracing::info!(
                                "[{}] Idle timeout after content emitted. Gracefully completing turn to prevent retry deadlock.",
                                trace_id
                            );
                            was_interrupted = true;
                            break;
                        } else if state.has_thinking {
                            tracing::info!(
                                "[{}] Idle timeout after thinking emitted. Forwarding to thinking recovery.",
                                trace_id
                            );
                            was_interrupted = true;
                            break;
                        } else {
                            let error_json = serde_json::json!({
                                "type": "error",
                                "error": {
                                    "type": "api_error",
                                    "message": report.client_message(),
                                    "function": report.function,
                                    "call_site": report.call_site(),
                                    "params": report.params,
                                }
                            });
                            yield Ok(state.emit("error", error_json));
                            error_emitted = true;
                            break;
                        }
                    }
                    yield Ok(Bytes::from(": ping\n\n"));
                }
            }
        }

        // [FIX #3621] Protocol Guard:
        // If an error event was emitted, terminate immediately!
        // Anthropic SSE protocol strictly prohibits emitting message_stop or other events after an error event.
        if error_emitted {
            return;
        }

        // [FIX #1732] Mandatory Flush remaining buffer on stream termination
        // Prevents hangs when the last SSE chunk doesn't end with a newline (network fragmentation)
        if !buffer.is_empty() {
             let line_str = String::from_utf8_lossy(&buffer);
             let line = line_str.trim();
             if !line.is_empty() {
                 tracing::debug!("[{}] SSE Termination: Flushing remaining {} bytes in buffer", trace_id, buffer.len());
                 if let Some(sse_chunks) = process_sse_line(line, &mut state, &trace_id, &email) {
                     for sse_chunk in sse_chunks {
                         yield Ok(sse_chunk);
                     }
                 }
             }
             buffer.clear();
        }

        // [FIX #3621] Interruption Truncation Notice:
        // If content generation was interrupted mid-stream, append a clear system notice
        // to the active text block so the user knows what happened, while finalizing normally.
        if was_interrupted
            && state.has_content
            && state.current_block_type() == crate::proxy::mappers::claude::streaming::BlockType::Text
        {
            let truncation_msg = "\n\n[System: Upstream connection interrupted. Response truncated by Antigravity.]";
            yield Ok(state.emit_delta(
                "text_delta",
                serde_json::json!({ "text": truncation_msg }),
            ));
        }

        // [FIX #Bug3] Post-thinking interruption recovery
        // If we have sent thinking but NO content (text/tool_use) and the stream ended,
        // we must provide a fallback to prevent loop hang on client side.
        if state.has_thinking && !state.has_content {
            tracing::warn!("[{}] Stream interrupted after thinking (No Content). Triggering recovery...", trace_id);

            // 1. Force close thinking block if open
            if state.current_block_type() == crate::proxy::mappers::claude::streaming::BlockType::Thinking {
               let close_chunks = state.end_block();
               for chunk in close_chunks {
                   yield Ok(chunk);
               }
            }

            // 2. Inject recovery text block to inform user
            let recovery_msg = "\n\n[System] Upstream model interrupted after thinking. (Recovered by Antigravity)";
            let start_chunks = state.start_block(
                crate::proxy::mappers::claude::streaming::BlockType::Text,
                serde_json::json!({ "type": "text", "text": recovery_msg })
            );
            for chunk in start_chunks { yield Ok(chunk); }
            let stop_chunks = state.end_block();
            for chunk in stop_chunks { yield Ok(chunk); }

            // 3. Mark as content received
            state.has_content = true;

            // 4. [FIX #Bug3] Explicitly emit message_delta + message_stop.
            // Previously, the recovery path relied on emit_force_stop() below,
            // but if message_stop_sent was already true (e.g. from a partial finish),
            // emit_force_stop() would be a no-op and the client would hang in loop.
            if !state.message_stop_sent {
                let recovery_usage = crate::proxy::mappers::claude::models::Usage {
                    input_tokens: 0,
                    output_tokens: 100, // Minimal non-zero to satisfy client
                    cache_read_input_tokens: None,
                    cache_creation_input_tokens: None,
                    server_tool_use: None,
                };
                let delta = serde_json::json!({
                    "type": "message_delta",
                    "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                    "usage": recovery_usage
                });
                yield Ok(state.emit("message_delta", delta));
                yield Ok(Bytes::from("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
                state.message_stop_sent = true;
            }
        } else if !state.has_content && !state.has_thinking {
            // [FIX #3359] Empty response recovery (e.g. single dot prompt health check)
            // If the upstream ended immediately without generating thinking or text content,
            // we must ensure message_start and at least one text block are sent before termination.
            if !state.message_start_sent {
                let dummy_start = serde_json::json!({
                    "responseId": format!("msg_recovered_{}", chrono::Utc::now().timestamp_millis()),
                    "modelVersion": "gemini-auto",
                });
                yield Ok(state.emit_message_start(&dummy_start));
            }

            let start_chunks = state.start_block(
                crate::proxy::mappers::claude::streaming::BlockType::Text,
                serde_json::json!({ "type": "text", "text": "." }),
            );
            for chunk in start_chunks {
                yield Ok(chunk);
            }
            let stop_chunks = state.end_block();
            for chunk in stop_chunks {
                yield Ok(chunk);
            }
            state.has_content = true;

            let recovery_usage = crate::proxy::mappers::claude::models::Usage {
                input_tokens: 1,
                output_tokens: 1,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                server_tool_use: None,
            };
            let delta = serde_json::json!({
                "type": "message_delta",
                "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                "usage": recovery_usage
            });
            yield Ok(state.emit("message_delta", delta));
        }

        if let Some(sid) = state.session_id.clone() {
            let acc = std::mem::take(&mut state.thinking_acc);
            acc.commit(&sid);
        }

        // Ensure termination events are sent
        for chunk in emit_force_stop(&mut state) {
            yield Ok(chunk);
        }
    })
}

/// 处理单行 SSE 数据
fn process_sse_line(
    line: &str,
    state: &mut StreamingState,
    trace_id: &str,
    email: &str,
) -> Option<Vec<Bytes>> {
    if !line.starts_with("data: ") {
        return None;
    }

    let data_str = line[6..].trim();
    if data_str.is_empty() {
        return None;
    }

    if data_str == "[DONE]" {
        let chunks = emit_force_stop(state);
        if chunks.is_empty() {
            return None;
        }
        return Some(chunks);
    }

    // 解析 JSON
    let json_value: serde_json::Value = match serde_json::from_str(data_str) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let mut chunks = Vec::new();

    // 解包 response 字段 (如果存在)
    let raw_json = json_value.get("response").unwrap_or(&json_value);

    // 发送 message_start
    if !state.message_start_sent {
        chunks.push(state.emit_message_start(raw_json));
    }

    // 捕获 groundingMetadata (Web Search)
    if let Some(candidate) = raw_json.get("candidates").and_then(|c| c.get(0)) {
        if let Some(grounding) = candidate.get("groundingMetadata") {
            // 提取搜索词
            if let Some(query) = grounding
                .get("webSearchQueries")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.get(0))
                .and_then(|v| v.as_str())
            {
                state.web_search_query = Some(query.to_string());
            }

            // 提取结果块
            if let Some(chunks_arr) = grounding.get("groundingChunks").and_then(|v| v.as_array()) {
                state.grounding_chunks = Some(chunks_arr.clone());
            } else if let Some(chunks_arr) = grounding
                .get("grounding_metadata")
                .and_then(|m| m.get("groundingChunks"))
                .and_then(|v| v.as_array())
            {
                state.grounding_chunks = Some(chunks_arr.clone());
            }
        }
    }

    // 处理所有 parts
    if let Some(parts) = raw_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|cand| cand.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(|p| p.as_array())
    {
        for part_value in parts {
            state.thinking_acc.ingest_part(part_value);
            if let Ok(part) = serde_json::from_value::<GeminiPart>(part_value.clone()) {
                let mut processor = PartProcessor::new(state);
                chunks.extend(processor.process(&part));
            }
        }
    }

    // Process grounding metadata (googleSearch results) and append as citations
    // [DISABLED] Temporarily disabled to fix Cherry Studio compatibility
    // Cherry Studio doesn't recognize "web_search_tool_result" type, causing validation errors
    // Search results are still displayed via Markdown text block in streaming.rs (lines 341-381)

    /*
    if let Some(grounding) = raw_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|cand| cand.get("groundingMetadata"))
    {
        if let Some(citation_chunks) = process_grounding_metadata(grounding, state) {
            chunks.extend(citation_chunks);
        }
    }
    */

    // 检查是否结束
    if let Some(finish_reason) = raw_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|cand| cand.get("finishReason"))
        .and_then(|f| f.as_str())
    {
        let usage = raw_json
            .get("usageMetadata")
            .and_then(|u| serde_json::from_value::<UsageMetadata>(u.clone()).ok());

        if let Some(ref u) = usage {
            let cached_tokens = u.cached_content_token_count.unwrap_or(0);
            let cache_info = if cached_tokens > 0 {
                format!(", Cached: {}", cached_tokens)
            } else {
                String::new()
            };

            tracing::info!(
                "[{}] ✓ Stream completed | Account: {} | In: {} tokens | Out: {} tokens{}",
                trace_id,
                email,
                u.prompt_token_count
                    .unwrap_or(0)
                    .saturating_sub(cached_tokens),
                u.candidates_token_count.unwrap_or(0),
                cache_info
            );
        }

        chunks.extend(state.emit_finish(Some(finish_reason), usage.as_ref()));
    }

    if chunks.is_empty() {
        None
    } else {
        Some(chunks)
    }
}

/// 发送强制结束事件
pub fn emit_force_stop(state: &mut StreamingState) -> Vec<Bytes> {
    if !state.message_stop_sent {
        let mut chunks = state.emit_finish(None, None);
        if chunks.is_empty() {
            chunks.push(Bytes::from(
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ));
            state.message_stop_sent = true;
        }
        return chunks;
    }
    vec![]
}

/// Process grounding metadata from Gemini's googleSearch and emit as Claude web_search blocks
#[allow(dead_code)] // Temporarily disabled for Cherry Studio compatibility, kept for future use
fn process_grounding_metadata(
    metadata: &serde_json::Value,
    state: &mut StreamingState,
) -> Option<Vec<Bytes>> {
    use serde_json::json;

    // Extract search queries and grounding chunks
    let search_queries = metadata
        .get("webSearchQueries")
        .and_then(|q| q.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    let grounding_chunks = metadata.get("groundingChunks").and_then(|c| c.as_array())?;

    if grounding_chunks.is_empty() {
        return None;
    }

    // Generate a unique tool_use_id
    let tool_use_id = format!(
        "srvtoolu_{}",
        crate::proxy::common::utils::generate_random_id()
    );

    // Build search results array
    let mut search_results = Vec::new();
    for chunk in grounding_chunks.iter() {
        if let Some(web) = chunk.get("web") {
            let title = web
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("Source");
            let uri = web.get("uri").and_then(|u| u.as_str()).unwrap_or("");
            if !uri.is_empty() {
                search_results.push(json!({
                    "url": uri,
                    "title": title,
                    "encrypted_content": "", // Gemini doesn't provide this
                    "page_age": null
                }));
            }
        }
    }

    if search_results.is_empty() {
        return None;
    }

    let search_query = search_queries
        .first()
        .map(|s| s.to_string())
        .unwrap_or_default();

    tracing::debug!(
        "[Grounding] Emitting {} search results for query: {}",
        search_results.len(),
        search_query
    );

    let mut chunks = Vec::new();

    // 1. Emit server_tool_use block (start)
    let server_tool_use_start = json!({
        "type": "content_block_start",
        "index": state.block_index,
        "content_block": {
            "type": "server_tool_use",
            "id": tool_use_id,
            "name": "web_search",
            "input": {
                "query": search_query
            }
        }
    });
    chunks.push(Bytes::from(format!(
        "event: content_block_start\ndata: {}\n\n",
        server_tool_use_start
    )));

    // server_tool_use block stop
    let server_tool_use_stop = json!({
        "type": "content_block_stop",
        "index": state.block_index
    });
    chunks.push(Bytes::from(format!(
        "event: content_block_stop\ndata: {}\n\n",
        server_tool_use_stop
    )));
    state.block_index += 1;

    // 2. Emit web_search_tool_result block (start)
    let tool_result_start = json!({
        "type": "content_block_start",
        "index": state.block_index,
        "content_block": {
            "type": "web_search_tool_result",
            "tool_use_id": tool_use_id,
            "content": search_results
        }
    });
    chunks.push(Bytes::from(format!(
        "event: content_block_start\ndata: {}\n\n",
        tool_result_start
    )));

    // web_search_tool_result block stop
    let tool_result_stop = json!({
        "type": "content_block_stop",
        "index": state.block_index
    });
    chunks.push(Bytes::from(format!(
        "event: content_block_stop\ndata: {}\n\n",
        tool_result_stop
    )));
    state.block_index += 1;

    Some(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_sse_line_done() {
        let mut state = StreamingState::new();
        let result = process_sse_line("data: [DONE]", &mut state, "test_id", "test@example.com");
        assert!(result.is_some());
        let chunks = result.unwrap();
        assert!(!chunks.is_empty());

        let all_text: String = chunks
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap_or_default())
            .collect();
        assert!(all_text.contains("message_stop"));
    }

    #[test]
    fn test_process_sse_line_with_text() {
        let mut state = StreamingState::new();

        let test_data = r#"data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]}}],"usageMetadata":{},"modelVersion":"test","responseId":"123"}"#;

        let result = process_sse_line(test_data, &mut state, "test_id", "test@example.com");
        assert!(result.is_some());

        let chunks = result.unwrap();
        assert!(!chunks.is_empty());

        // 应该包含 message_start 和 text delta
        let all_text: String = chunks
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap_or_default())
            .collect();

        assert!(all_text.contains("message_start"));
        assert!(all_text.contains("content_block_start"));
        assert!(all_text.contains("Hello"));
    }

    #[tokio::test]
    async fn test_thinking_only_interruption_recovery() {
        use futures::StreamExt;

        // 1. 模拟一个只发送 Thinking 然后就结束的流
        let mock_stream = async_stream::stream! {
            // 发送 Thinking 块
            let thinking_json = serde_json::json!({
                "candidates": [{
                    "content": {
                        "parts": [{ "text": "Thinking...", "thought": true }]
                    }
                }],
                "modelVersion": "gemini-2.0-flash-thinking",
                "responseId": "msg_interrupted"
            });
            yield Ok::<_, String>(bytes::Bytes::from(format!("data: {}\n\n", thinking_json)));

            // 然后突然结束 (没有 Text, 没有 Usage, 直接 None)
        };

        // 2. 创建转换后的流
        let mut claude_stream = create_claude_sse_stream(
            Box::pin(mock_stream),
            "trace_test".to_string(),
            "test@example.com".to_string(),
            None,
            false,
            1_000,
            None,
            1,          // message_count
            None,       // client_adapter
            Vec::new(), // registered_tool_names
        );

        // 3. 收集输出
        let mut all_chunks = Vec::new();
        while let Some(result) = claude_stream.next().await {
            if let Ok(bytes) = result {
                all_chunks.push(String::from_utf8(bytes.to_vec()).unwrap());
            }
        }
        let output = all_chunks.join("");

        // 4. 验证恢复逻辑
        // 必须包含 Thinking
        assert!(output.contains("Thinking..."));

        // 必须包含恢复的系统提示
        assert!(output.contains("Recovered by Antigravity"));

        // 必须包含模拟的 Usage
        assert!(output.contains("\"usage\":"));
        assert!(output.contains("\"output_tokens\":100")); // Should contain the recovery usage
    }

    #[tokio::test]
    async fn test_create_claude_sse_stream_mid_stream_interruption_gracefully_recovers() {
        use futures::StreamExt;

        // 模拟一个发送了部分内容后发生网络中断的流（如用户遇到的 "1. 萌系 Claude 牛" 之后断流）
        let mock_stream = async_stream::stream! {
            yield Ok::<_, String>(bytes::Bytes::from("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello world\"}]}}]}\n\n"));
            yield Err("error reading a body from connection: connection reset by peer".to_string());
        };

        let mut claude_stream = create_claude_sse_stream(
            Box::pin(mock_stream),
            "trace_mid_err_test".to_string(),
            "test@example.com".to_string(),
            None,
            false,
            1_000,
            None,
            1,
            None,
            Vec::new(),
        );

        let mut all_chunks = Vec::new();
        while let Some(result) = claude_stream.next().await {
            if let Ok(bytes) = result {
                all_chunks.push(String::from_utf8(bytes.to_vec()).unwrap());
            }
        }
        let output = all_chunks.join("");

        // 1. 必须包含已输出的内容
        assert!(
            output.contains("Hello world"),
            "Output must contain text emitted before error"
        );

        // 2. 必须注入截断系统提示
        assert!(
            output.contains("Upstream connection interrupted. Response truncated by Antigravity"),
            "Output must contain graceful truncation notice"
        );

        // 3. 必须包含正常收尾的 message_delta 和 message_stop，使客户端顺利完成当前轮次
        assert!(
            output.contains("event: message_delta"),
            "Output must contain message_delta"
        );
        assert!(
            output.contains(r#""stop_reason":"end_turn""#),
            "Output must end with stop_reason end_turn"
        );
        assert!(
            output.contains("event: message_stop"),
            "Output must contain message_stop"
        );

        // 4. [FIX #3621 关键断言] 严禁在已输出内容后发送 event: error 或 overloaded_error！
        // 彻底切断导致 Claude Code CLI / Anthropic SDK 产生 20+ 分钟恶性指数退避重试死锁的根因
        assert!(
            !output.contains("event: error"),
            "Must NOT emit event: error after content was already emitted"
        );
        assert!(
            !output.contains(r#""type":"overloaded_error""#),
            "Must NOT emit overloaded_error which triggers infinite client retries"
        );
    }

    #[tokio::test]
    async fn test_create_claude_sse_stream_initial_error_emits_standard_api_error_without_trailing_events(
    ) {
        use futures::StreamExt;

        // 模拟一个在发出任何内容前就发生连接错误的流
        let mock_stream = async_stream::stream! {
            yield Err::<bytes::Bytes, _>("error connecting to upstream: connection refused".to_string());
        };

        let mut claude_stream = create_claude_sse_stream(
            Box::pin(mock_stream),
            "trace_init_err_test".to_string(),
            "test@example.com".to_string(),
            None,
            false,
            1_000,
            None,
            1,
            None,
            Vec::new(),
        );

        let mut all_chunks = Vec::new();
        while let Some(result) = claude_stream.next().await {
            if let Ok(bytes) = result {
                all_chunks.push(String::from_utf8(bytes.to_vec()).unwrap());
            }
        }
        let output = all_chunks.join("");

        // 1. 必须包含 event: error
        assert!(
            output.contains("event: error"),
            "Output must contain event: error"
        );

        // 2. 错误类型必须是 Anthropic 标准的 api_error，绝不能是引发恶性重试的 overloaded_error
        assert!(
            output.contains(r#""type":"api_error""#),
            "Error event must contain standard Anthropic type 'api_error', got: {}",
            output
        );
        assert!(
            !output.contains(r#""type":"overloaded_error""#),
            "Error event must not use overloaded_error"
        );
        assert!(
            !output.contains(r#""type":"stream_error""#),
            "Error event must not leak internal non-standard 'stream_error'"
        );

        // 3. [FIX #3621 关键断言] 发生 error 后必须立即终止，严禁追加发送 message_stop 破坏协议状态机！
        assert!(
            !output.contains("event: message_stop"),
            "Must NOT emit message_stop after event: error"
        );

        // 4. 同时必须保留诊断信息
        assert!(output.contains("fn=create_claude_sse_stream"));
    }
}
