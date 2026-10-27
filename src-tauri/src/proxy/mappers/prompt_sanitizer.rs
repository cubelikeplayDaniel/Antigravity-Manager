//! Prompt Sanitizer Pipeline Module
//!
//! 提供中转报文生成后、发往上游出站前的提示词专用清洗流水线节点。
//! 严格且精准地剥离第三方客户端（Claude Code CLI / VS Code CC / Cherry Studio 等）
//! 在 system / user 块中注入的计费元数据伪 Header（如 `x-anthropic-billing-header` 与
//! `cc_version` / `cc_entrypoint` / `cch` 签名）及 Claude Agent SDK 前导指纹声明，
//! 防止触发 Google Cloud Code 上游 WAF 的特征拦截（虚假 429 RESOURCE_EXHAUSTED）
//! 进而导致全局账号池 503 级联封锁。
//!
//! 核心设计与防误杀铁律：
//! 1. 深度保护代码块：自动提取并保护所有围栏代码块（```）与行内代码（`），代码内容 100% 豁免；
//! 2. 严禁碰触会话唯一性（Zero Session Touch）：绝不清洗或过滤任何 session 相关字段（包括
//!    `x-jeikcode-session-id`, `x-session-id` 等）；会话唯一性由
//!    `SessionScope` 按照严格优先级链条独立处理，本模块对所有 session 标识保持 100% 原样透传；
//! 3. 严禁碰触用户自定义分割符与标签（Zero Delimiter Touch）：绝不删除 `=== ... ===`、`--- ... ---`
//!    以及 XML 标签（如 `<environment>`, `<workflow_and_execution_discipline>` 等），保证如
//!    JeikCode 等 AI 编码框架的用户与系统指令结构完好无损；
//! 4. 严禁裁剪或假定 IDE 反刍文本：不预设删除任何用户自然语言与业务指令；
//! 5. 全链路审计一致：中转报文生成并填充完思考块后统一在流水线层介入，保证协议无关且写进数据库与转出的报文真实一致；
//! 6. 思考块首位铁律（Thinking Block at Index 0）：清洗完后必须确保思考块在 parts 中严格位于首位，
//!    且思考块文本严禁执行任何破坏性修改，保全数字签名与哈希一致性；
//! 7. 物理剔除空 Part 与空 systemInstruction：清洗后产生的空 Part 物理移出数组，若 systemInstruction
//!    为空则物理注销，杜绝 Google API 格式校验异常。
//! 8. 两轨分治（Two-Track Separation）：节点内部严格区分「Header 轨」与「System 轨」，杜绝规则互相污染：
//!    · Header 轨（`clean_text`）：剥离文本内嵌的计费伪 Header 与高危客户端指纹声明，对**全部文本**
//!      （systemInstruction / contents / user）一致生效；
//!    · System 轨（`normalize_system_identity`）：仅在**系统提示词头部窗口**（每个系统提示词块的
//!      前 `IDENTITY_SCAN_MAX_SENTENCES` 句）内，把「身份归属声明句」归一化为中性身份，
//!      **绝不触碰** user / tool 文本，也绝不触碰管道自身的系统提示词。
//!    该分治使四协议共享同一份身份归一化规则（AGENTS.md「Pipeline First」：适配层不做协议专用清洗特例）。

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

/// 代码块保护正则：隔离多行围栏代码块 ```...``` 与行内反引号 `...`
static RE_CODE_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?ms)(```[\s\S]*?```|`[^`\r\n]+`)").unwrap());

/// 触发上游 Google WAF 拦截的高危客户端伪 Header 与特征声明正则（仅在非代码区域生效）：
/// 1) 通用泛化匹配各类客户端注入的 `*-billing*` 伪 Header 行（如 `x-anthropic-billing-header:`, `x-billing:`, `x-client-billing:`, `anthropic-billing-header:` 等）
/// 2) 匹配任何以 `x-` 开头且携带 Claude Code CLI 计费签名特征（`cc_version`, `cc_entrypoint`, `cch=`）的伪 Header
/// 3) 匹配 mid-paragraph（嵌入在段落中间）的 `x-anthropic-billing-header:` 及其后续声明
/// 4) 匹配 Claude Agent SDK 专属前导指纹声明 (`You are a Claude agent, built on Anthropic's Claude Agent SDK.`)
/// 严格排除任何 `session` 关键字，确保用户提问与会话跟踪完全免受干扰。
static RE_WAF_TRIGGER_HEADERS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?im)^\s*(?:x-[a-z0-9_-]*billing[a-z0-9_-]*|[a-z0-9_-]+-billing-(?:header|metadata|token|info)):\s*[^\r\n]*(\r?\n)?",
        r"|^\s*x-[a-z0-9_-]+:\s*[^\r\n]*(?:cc_version|cc_entrypoint|cc_workload|cc_is_subagent|cc_prev_req|cc_prompt_id|cc_turn_origin|cch=)[^\r\n]*(\r?\n)?",
        r"|(?i)x-anthropic-billing-header:\s*[^\r\n]*",
        r"|(?i)You are a Claude agent, built on Anthropic's Claude Agent SDK\.(\r?\n)?",
        r"|(?i)You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK\.(\r?\n)?"
    ))
    .unwrap()
});

/// 连续多余空行收拢正则（剥离元数据后若产生 3 个及以上连续换行，收拢为 2 个换行以保持自然段落）
static RE_MULTI_NEWLINE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n{3,}").unwrap());

/// 代码块占位符单趟还原正则（杜绝顺序字符串替换导致的嵌套膨胀炸弹与 $2^N$ 性能陷阱）
static RE_CODE_BLOCK_PLACEHOLDER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"__PROMPT_SANITIZER_CODE_BLOCK_(\d+)__").unwrap());

/// 匹配任意 XML 风格标签候选块 `<tag ...>inner</tag>`
static RE_XML_TAG_CANDIDATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)(<([a-zA-Z0-9_\-]+)(?:\s+[^>]*)?>)([\s\S]*?)(</([a-zA-Z0-9_\-]+)>)").unwrap()
});

/// 触发上游风控拦截的知名竞品厂牌正则（大小写不敏感，统一归一化为 Google）
static RE_COMPETITOR_BRANDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        // 英文竞品厂牌（使用单词边界，大小写不敏感）
        r"(?i)\b(?:openai|anthropic|qwen|bytedance|tencent|xiaomi|huawei|deepseek|baidu|mistral|cohere)\b",
        r"|",
        // 中文竞品厂牌及知名模型代号
        r"(?:字节跳动|腾讯|小米|华为|通义千问|通义灵码|通义|百度|文心一言|文心快码|深度求索|豆包|混元)"
    ))
    .unwrap()
});

// ============================ System 轨：身份声明归一化 ============================
//
// 触发上游 WAF 伪限流（虚假 429 RESOURCE_EXHAUSTED）的是**身份归属声明**，而非模型能力或请求体量：
// 上游对"第三方 Agent 框架 + 工具调用能力"的组合施加更严规则集，一旦识别出客户端自我介绍中的
// 厂商 / 产品 / 竞品模型指纹即拒绝该请求，网关若原样透传则每个账号都会被拒，并被误记为账号限流
// 进而波及整池（详见 issue #3507 / #3506，以及 Codex `based on GPT-x` 的 #3444 / #3489）。
//
// Agent 客户端数以千计且会持续出现，无法穷举，因此归一化必须**广谱**：只要一句自我介绍同时具备
// 「身份开场白 + 身份名词 + 归属/版本声明」三要素，就整体归一化为中性身份，而非只处理已知厂商。

/// 身份归一化扫描窗口：扫描每个系统提示词块的前 8 句或前 1500 字符。
/// 扩展窗口能够可靠穿透前置插件上下文/环境垫片（如 OpenClaw 的 plugin-injected context），
/// 同时限制在头部以确保正文（文档、代码注释、用户需求）中的正常引用 100% 不被误伤。
const IDENTITY_SCAN_MAX_SENTENCES: usize = 8;
const IDENTITY_SCAN_MAX_CHARS: usize = 1500;

/// 官方原生 Antigravity 助手身份声明（完全对齐官方 Antigravity IDE 提示词模板）
pub const OFFICIAL_ANTIGRAVITY_IDENTITY: &str =
    "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.";

/// 归一化后的身份声明别名（统一对齐为官方 Antigravity 助手，兼容历史引用）
#[allow(dead_code)]
pub const NEUTRAL_IDENTITY: &str = OFFICIAL_ANTIGRAVITY_IDENTITY;

/// 身份声明句归一化正则（广谱匹配，仅在系统提示词头部窗口内生效）。
///
/// 形态 = A 身份开场白 + B 身份名词短语 + C 归属/版本/宿主声明 + D 归属对象 + E 句读：
/// ```text
/// You are Hermes Agent, an intelligent AI assistant created by Nous Research.   → You are Antigravity...
/// You are Codex, an advanced coding agent based on GPT-6.                       → You are Antigravity...
/// You are an AI agent created by Example Corp.                                  → You are Antigravity...
/// You are an intelligent programming assistant integrated into Cursor editor.  → You are Antigravity...
/// You are a personal assistant running inside OpenClaw.                         → You are Antigravity...
/// ```
/// 防误杀设计（四条硬约束，缺一不可）：
/// 1. **必须具备身份名词与归属声明或特定已知客户端开场**；
/// 2. **归属对象取到句读边界（`.` `,` `。` `，` 换行）即止，且禁止跨越 XML 标签** —— 从结构上根除
///    "跨行吞噬后续规则"的缺陷，同时满足 Zero Delimiter Touch；
/// 3. **只替换声明句本身** —— 归属声明之后的内容（含逗号续写的功能指令）逐字保留；
/// 4. **过渡窗口 ≤ 8 字符**：身份名词与归属动词之间的桥接文本必须极短，防止跨子句误删。
static RE_IDENTITY_DECLARATION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?:",
        // 英文支：开场白（人称开场及扮演式） + 可选名词短语 + 动词 + 归属对象
        r"(?i:\b(?:you\s+are|you're|i\s+am|i'm|act\s+as)\b[\s,，:：]*)",
        r"(?i:(?:an?\s+)?(?:[\w'\-]+[\s,，]+){0,8}(?:ai[\s,，]+)?(?:agent\b|assistant\b|ai\b|tool\b|cli\b|programmer\b|companion\b|engineer\b|bot\b))?",
        // 动词前导：支持短名称/版本号 (如 Grok 4.6) 及可选逗号/从句引导词 (如 ", created by" 或 ", which is built by")
        // 严禁跨越逗号包含新主语或连词 (如 ", and the config was created by")，桥接字符类严格排除逗号
        r"(?i:(?:[^\s.,，!?。！？;；\r\n<>]|\d+\.\d+|[\t ]){0,15}?[\s,，]*(?:(?:which|that|who)\s+(?:is|was)\s+)?(?:\b(?:created|built|made|developed|designed|trained|powered|maintained|published|released|provided|authored|written)\s+(?:by|on|upon|at|for)\s+|\bby\s+|based\s+on\s+|running\s+(?:inside|in|within|on)\s+|integrated\s+(?:into|in)\s+))",
        // 归属对象：支持跨越数字间的版本号点号 (如 3.8, 4.5) 直到句读边界
        r"(?:[^\s.,，。!?！？;；\r\n<>]|\d+\.\d+|[\t ])+",
        r"|",
        // 中文支：你是/我是 + 包含开发/制作/构建/基于/推出 等归属特征，整句收敛到句读
        r"(?:你是|我是)[\s,，:：]*[^.!?。！？\r\n<>]{0,50}?(?:由|开发|制作|构建|训练|推出|基于|运行[在于])[^.!?。！？\r\n<>]{1,60}",
        r")",
        r"([.,，。!?！？;；]?)"
    ))
    .unwrap()
});

/// 知名特定客户端与 Harness 开场白正则（涵盖 OpenCode, OpenClaw, Claude Code CLI, Cursor, Cascade, Cline 等）
static RE_KNOWN_CLIENT_DECLARATION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:you\s+are|you're)\s+(?:",
        r"claude\s+code[\s,，]+(?:anthropic's\s+)?official\s+cli\s+for\s+claude(?:[\s,，]+running\s+within\s+(?:the\s+)?claude\s+agent\s+sdk)?",
        r"|opencode(?:\s*,\s*an?\s+interactive\s+cli\s+tool(?:\s+that\s+helps\s+users\s+with\s+software\s+engineering\s+tasks)?)?",
        r"|(?:an?\s+)?personal\s+assistant\s+running\s+(?:inside|in|within)\s+openclaw",
        r"|openclaw",
        r"|cursor(?:\s+ai)?(?:\s*,\s*an?\s+intelligent\s+programming\s+assistant(?:\s+integrated\s+into\s+cursor(?:\s+editor)?)?)?",
        r"|cascade(?:\s*,\s*an?\s+ai\s+pair\s+programmer(?:\s+by\s+codeium)?)?",
        r"|cline(?:\s*,\s*an?\s+(?:highly\s+skilled\s+)?software\s+engineer(?:\s+with\s+extensive\s+knowledge\s+in\s+many\s+programming\s+languages)?)?",
        r"|roo\s+code",
        r"|aider(?:\s*,\s*an?\s+expert\s+software\s+engineer)?",
        r"|kilocode(?:\s*,\s*an?\s+ai\s+coding\s+assistant)?",
        r"|dsh(?:\s*,\s*an?\s+automated\s+software\s+development\s+harness)?",
        r"|devin(?:\s*,\s*an?\s+autonomous\s+software\s+engineer)?",
        r"|(?:[\w'\-]+(?:code|studio|claw)|[\w'\-]+\s+(?:code|studio|claw)|pi)(?:\s+(?:ai\s+)?(?:coding\s+)?(?:agent|assistant))?",
        r")\b",
        r"([.,，。!?！？;；]?)"
    ))
    .unwrap()
});

/// 身份声明归一化的快速前置特征（命中任一才进入正则流程，规避 33k 级提示词的全量正则开销）
const IDENTITY_FAST_MARKERS: &[&str] = &[
    // 厂商归属与关系动词
    "created by",
    "built by",
    "built on",
    "built for",
    "made by",
    "developed by",
    "designed by",
    "designed for",
    "trained by",
    "powered by",
    "maintained by",
    "published by",
    "released by",
    "provided by",
    "authored by",
    "written by",
    "based on",
    "running inside",
    "running within",
    "running in",
    "running on",
    "integrated into",
    "integrated in",
    // 身份+归属短语
    "agent by",
    "assistant by",
    "ai by",
    "cli by",
    "bot by",
    "programmer by",
    "engineer by",
    // 知名第三方客户端与平台特征指纹
    "claude code",
    "claude agent",
    "opencode",
    "openclaw",
    "cursor",
    "cascade",
    "codeium",
    "aider",
    "cline",
    "roo code",
    "kilocode",
    "hermes",
    "codex",
    "anthropic",
    "dsh",
    "devin",
    "inflection",
    "grok",
    "xai",
    "code",
    "studio",
    "claw",
    "pi",
    "jeikcode",
    "atomcode",
    // 竞品厂牌标记
    "openai",
    "anthropic",
    "qwen",
    "bytedance",
    "tencent",
    "xiaomi",
    "huawei",
    "deepseek",
    "baidu",
    "字节跳动",
    "腾讯",
    "小米",
    "华为",
    "通义",
    "豆包",
    "混元",
    // 中文特征标记
    "由",
    "基于",
    "开发",
    "助手",
    "助理",
    "运行在",
    "运行于",
];

/// Claude Agent SDK 注入的独立身份块（整串等值匹配）
const CLAUDE_AGENT_SDK_IDENTITY: &str =
    "You are a Claude agent, built on Anthropic's Claude Agent SDK.";
/// 历史保留的 Claude Code CLI 身份声明（整串等值匹配）
const CLAUDE_CODE_CLI_IDENTITY: &str = "You are Claude Code, Anthropic's official CLI for Claude.";
/// Claude Code CLI 在 Claude Agent SDK 运行时注入的身份声明（整串等值匹配）
const CLAUDE_AGENT_SDK_CLI_IDENTITY: &str =
    "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.";

/// Claude Desktop 注入的单行计费元数据前缀（issue #3452：与大量工具组合会触发上游 429）。
/// 判定**不区分 model** —— 任何客户端注入的风险元数据都必须清洗。
const BILLING_METADATA_PREFIX: &str = "x-anthropic-billing-header:";

/// 管道自身的系统提示词分界标记（混入时剥掉，避免污染上游报文）
const SYSTEM_PROMPT_END_MARKERS: [&str; 2] = ["--- [SYSTEM_PROMPT_END] ---", "[SYSTEM_PROMPT_END]"];

/// 管道自身的官方身份文本（全局提示词混入时整段剥掉，避免重复声明身份）
const SELF_IDENTITY_BLOCK: &str = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\nYou are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n**Absolute paths only**\n**Proactiveness**";

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SanitizerScope {
    System,
    LeadingUser,
    General,
}

pub struct PromptSanitizer;

impl PromptSanitizer {
    /// 对单段提示词文本进行通用、高精度的净化：
    /// 1. 快速检查是否包含高危 WAF 拦截触发词（`billing`, `cc_version`, `cc_entrypoint`），未包含直接原样返回；
    /// 2. 提取并保护所有代码块，使其免受任何正则影响；
    /// 3. 仅剥离触发 WAF 的客户端计费伪 Header，绝不修改任何会话 ID、XML 标签或 `=== ... ===` 分隔符；
    /// 4. 完整恢复受保护的代码块；
    /// 5. 规范化换行，保留所有多行正文排版。
    pub fn clean_text(text: &str) -> String {
        // 快速前置检查：若文本不包含高危特征，直接原样返回，零开销
        let lower = text.to_lowercase();
        let has_suspect = lower.contains("billing")
            || lower.contains("cc_version")
            || lower.contains("cc_entrypoint")
            || lower.contains("cc_workload")
            || lower.contains("cc_is_subagent")
            || lower.contains("cc_prev_req")
            || lower.contains("cc_prompt_id")
            || lower.contains("cc_turn_origin")
            || lower.contains("cch=")
            || lower.contains("claude agent sdk");

        if !has_suspect {
            return text.to_string();
        }

        // 步骤 1：保护代码块
        let mut placeholders: Vec<String> = Vec::new();
        let protected_text = RE_CODE_BLOCK.replace_all(text, |caps: &regex::Captures| {
            let idx = placeholders.len();
            placeholders.push(caps[0].to_string());
            format!("__PROMPT_SANITIZER_CODE_BLOCK_{}__", idx)
        });

        // 步骤 2：对非代码区域仅剥离触发 WAF 的高危伪 Header
        let pass1 = RE_WAF_TRIGGER_HEADERS.replace_all(&protected_text, "");

        // 步骤 3：单趟无递归还原受保护的代码块
        let restored = RE_CODE_BLOCK_PLACEHOLDER.replace_all(&pass1, |caps: &regex::Captures| {
            if let Ok(idx) = caps[1].parse::<usize>() {
                if let Some(code) = placeholders.get(idx) {
                    return code.clone();
                }
            }
            caps[0].to_string()
        });

        // 步骤 4：连续空行收拢（若因删除单行产生多余换行，保持正常双换行段落结构）
        let normalized = RE_MULTI_NEWLINE.replace_all(&restored, "\n\n");

        normalized.trim().to_string()
    }

    /// 计算系统提示词的**头部窗口**：返回从开头起、跨越前 `IDENTITY_SCAN_MAX_SENTENCES` 句或 `IDENTITY_SCAN_MAX_CHARS` 字符的切片。
    /// 句界 = `.` `!` `?` `。` `！` `？`，或**空行**（连续两个 `\n`，兼容 `\r\n`）；普通折行不计为句界。
    fn identity_head_region(text: &str) -> &str {
        let mut sentence_count = 0usize;
        let mut prev_newline = false;

        for (idx, ch) in text.char_indices() {
            let is_newline = ch == '\n';
            let is_terminator = matches!(ch, '.' | '!' | '?' | '。' | '！' | '？');

            if is_terminator || (is_newline && prev_newline) {
                sentence_count += 1;
                if sentence_count >= IDENTITY_SCAN_MAX_SENTENCES {
                    return &text[..idx + ch.len_utf8()];
                }
            }

            if is_newline {
                prev_newline = true;
            } else if ch != '\r' {
                prev_newline = false;
            }

            if idx >= IDENTITY_SCAN_MAX_CHARS {
                return &text[..idx + ch.len_utf8()];
            }
        }

        text
    }

    /// System / User 轨文本身份声明归一化：
    /// 归一化一段文本内部的所有身份归属声明句与已知客户端开场白为官方 Antigravity 声明。
    /// 若 `replace_brands` 为 true（System 轨专用），则额外将正文中的竞品厂牌替换为 Google；
    /// 若为 false（User 轨专用），绝不碰触任何竞品厂牌名称，100% 捍卫用户业务提问的原貌。
    fn normalize_text_identity(text: &str, replace_brands: bool) -> String {
        let matches_broad = RE_IDENTITY_DECLARATION.is_match(text);
        let matches_known = RE_KNOWN_CLIENT_DECLARATION.is_match(text);
        let matches_brands = replace_brands && RE_COMPETITOR_BRANDS.is_match(text);
        if !matches_broad && !matches_known && !matches_brands {
            return text.to_string();
        }

        // 步骤 1：保护代码块，使其免于身份归一与厂牌替换的任何影响
        let mut placeholders: Vec<String> = Vec::new();
        let protected_text = RE_CODE_BLOCK.replace_all(text, |caps: &regex::Captures| {
            let idx = placeholders.len();
            placeholders.push(caps[0].to_string());
            format!("__PROMPT_SANITIZER_CODE_BLOCK_{}__", idx)
        });

        // 步骤 2：归一化身份声明句（逗号续写场景保留逗号，避免出现 ", ," 或 ", and" 断裂）
        // 2.1 广谱归属声明归一化
        let pass1 = RE_IDENTITY_DECLARATION.replace_all(
            &protected_text,
            |caps: &regex::Captures| match caps.get(1).map(|m| m.as_str()).unwrap_or("") {
                "," | "，" => format!("{},", OFFICIAL_ANTIGRAVITY_IDENTITY),
                _ => OFFICIAL_ANTIGRAVITY_IDENTITY.to_string(),
            },
        );

        // 2.2 知名特定客户端开场白归一化（如 Claude Code CLI 开场白、*code、*studio、*claw、pi 等）
        let pass2 = RE_KNOWN_CLIENT_DECLARATION.replace_all(&pass1, |caps: &regex::Captures| {
            match caps.get(1).map(|m| m.as_str()).unwrap_or("") {
                "," | "，" => format!("{},", OFFICIAL_ANTIGRAVITY_IDENTITY),
                _ => OFFICIAL_ANTIGRAVITY_IDENTITY.to_string(),
            }
        });

        // 2.3 竞品厂牌（OpenAI、Anthropic、Qwen、字节跳动、腾讯、小米、华为等）统一归一化为 Google
        // 铁律：仅在系统轨（replace_brands == true）执行，用户轨绝对严禁替换竞品厂牌！
        let normalized = if replace_brands {
            RE_COMPETITOR_BRANDS
                .replace_all(&pass2, "Google")
                .into_owned()
        } else {
            pass2.into_owned()
        };

        // 步骤 3：单趟无递归还原受保护的代码块
        let restored = RE_CODE_BLOCK_PLACEHOLDER
            .replace_all(&normalized, |caps: &regex::Captures| {
                if let Ok(idx) = caps[1].parse::<usize>() {
                    if let Some(code) = placeholders.get(idx) {
                        return code.clone();
                    }
                }
                caps[0].to_string()
            })
            .into_owned();

        restored
    }

    /// System 轨：对系统提示词全量文本及任意 XML 标签内部的「身份归属声明句」与已知客户端开场白归一化为官方 Antigravity 身份。
    ///
    /// 执行策略：
    /// 1. 不设前序行数与字符数硬截断，全量扫描系统提示词中的身份声明句并替换为官方 Antigravity 助手；
    /// 2. 深入检测任意 `<xxx ...> ... </xxx>` 标签内部的内容，若包含客户端身份声明同样归一化；
    /// 3. 全程深度保护代码块（``` 与行内 `），标签本身及后续业务指令逐字完整保留。
    pub fn normalize_system_identity(text: &str) -> String {
        let lower = text.to_lowercase();

        // 核心铁律：快速前置短路检查（无任何归属类或已知客户端特征词则零开销返回）
        if !IDENTITY_FAST_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
        {
            return text.to_string();
        }

        // 步骤 1：先按标准清洗逻辑归一化整段文本中的身份声明与厂牌 (replace_brands = true)
        let pass1 = Self::normalize_text_identity(text, true);

        // 步骤 2：若发现有 XML 风格标签，深入到任意 <xxx ...> ... </xxx> 内部匹配其内容
        // 预先保护 pass1 中的代码块，确保标签替换绝不破坏代码
        let mut code_placeholders: Vec<String> = Vec::new();
        let pass1_protected = RE_CODE_BLOCK.replace_all(&pass1, |caps: &regex::Captures| {
            let idx = code_placeholders.len();
            code_placeholders.push(caps[0].to_string());
            format!("__PROMPT_SANITIZER_CODE_BLOCK_{}__", idx)
        });

        let pass2 = RE_XML_TAG_CANDIDATE.replace_all(&pass1_protected, |caps: &regex::Captures| {
            let open_name = &caps[2];
            let close_name = &caps[5];
            if !open_name.eq_ignore_ascii_case(close_name) {
                return caps[0].to_string();
            }

            let inner = &caps[3];
            let inner_lower = inner.to_lowercase();
            if !IDENTITY_FAST_MARKERS
                .iter()
                .any(|marker| inner_lower.contains(marker))
            {
                return caps[0].to_string();
            }

            let normalized_inner = Self::normalize_text_identity(inner, true);
            if normalized_inner != inner {
                format!("{}{}{}", &caps[1], normalized_inner, &caps[4])
            } else {
                caps[0].to_string()
            }
        });

        let restored = RE_CODE_BLOCK_PLACEHOLDER.replace_all(&pass2, |caps: &regex::Captures| {
            if let Ok(idx) = caps[1].parse::<usize>() {
                if let Some(code) = code_placeholders.get(idx) {
                    return code.clone();
                }
            }
            caps[0].to_string()
        });

        restored.into_owned()
    }

    /// User 轨：把首轮对话（或客户端注入的预置提示词）中的「身份归属声明句」与已知客户端开场白归一化为官方 Antigravity 身份。
    /// 铁律：绝对严禁执行竞品厂牌替换（replace_brands = false），用户提问中的 OpenAI、Anthropic、
    /// 腾讯、字节跳动等自然语言 100% 保持原始状态！
    pub fn normalize_user_identity(text: &str) -> String {
        let lower = text.to_lowercase();
        if !IDENTITY_FAST_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
        {
            return text.to_string();
        }

        Self::normalize_text_identity(text, false)
    }

    /// 清洗 parts 数组中的所有文本节点，并严格捍卫：
    /// 1. 思考块受 thoughtSignature 严格保护，字节级绝对不可变；
    /// 2. 物理剔除清洗后产生的纯空文本 Part（避免上游 400/429 报错）；
    /// 3. 清洗后若存在思考块，强制保序确保思考块严格位于首位 (Index 0)；
    /// 4. `system_scope` 决定是否叠加 System 轨（身份归一化）—— 仅系统提示词为 true。
    /// 客户端身份归一化：已知客户端身份（Claude Agent SDK / Claude Code CLI）对齐为官方 Antigravity 身份。
    pub fn normalize_client_identity(text: &str) -> &str {
        if text == CLAUDE_AGENT_SDK_IDENTITY
            || text == CLAUDE_CODE_CLI_IDENTITY
            || text == CLAUDE_AGENT_SDK_CLI_IDENTITY
        {
            OFFICIAL_ANTIGRAVITY_IDENTITY
        } else {
            text
        }
    }

    /// 是否为客户端注入的单行计费元数据（issue #3452：与大量工具组合会触发上游 429）。
    /// **不区分 model** —— 风险元数据来自客户端注入，任何模型 / 协议下命中即视为风险。
    pub fn is_billing_metadata(text: &str) -> bool {
        let t = text.trim();
        t.starts_with(BILLING_METADATA_PREFIX) && !t.contains('\n') && !t.contains('\r')
    }

    /// 剥离管道自身的提示词分界标记与官方身份文本（原适配层 `clean_system_prompt_text`）。
    /// 注意：不含 `clean_text` —— Header 轨已在 `sanitize_parts_core` 中统一执行，避免重复。
    pub fn strip_pipeline_markers(text: &str) -> String {
        let mut s = text.to_string();
        for marker in SYSTEM_PROMPT_END_MARKERS {
            if s.contains(marker) {
                s = s.replace(marker, "");
            }
        }
        if s.contains(SELF_IDENTITY_BLOCK) {
            s = s.replace(SELF_IDENTITY_BLOCK, "");
        }
        s.trim().to_string()
    }

    fn sanitize_parts_core(parts: &mut Vec<Value>, scope: SanitizerScope) -> usize {
        let mut cleaned_count = 0;

        // 0. 物理剔除客户端注入的计费元数据 Part（issue #3452）
        //    不分 model / 协议：命中即整块移除 —— 风险来自客户端注入，与模型无关。
        let before = parts.len();
        parts.retain(|part| {
            let is_thought = part
                .get("thought")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || part.get("thoughtSignature").is_some()
                || part.get("thought_signature").is_some();
            if is_thought {
                return true;
            }
            match part.get("text").and_then(Value::as_str) {
                Some(t) => !Self::is_billing_metadata(t),
                None => true,
            }
        });
        cleaned_count += before - parts.len();

        for part in parts.iter_mut() {
            if let Some(obj) = part.as_object_mut() {
                // 思考块受数字签名 (thoughtSignature) 严格保护，其文本必须保持字节级绝对不可变，严禁执行清洗
                if obj.get("thought").and_then(Value::as_bool).unwrap_or(false)
                    || obj.contains_key("thoughtSignature")
                {
                    continue;
                }

                if let Some(text_val) = obj.get("text").and_then(Value::as_str) {
                    // 客户端身份映射（整串等值）—— 仅系统提示词与首轮用户注入
                    let mapped = match scope {
                        SanitizerScope::System | SanitizerScope::LeadingUser => {
                            Self::normalize_client_identity(text_val)
                        }
                        SanitizerScope::General => text_val,
                    };
                    // Header 轨（全文本生效）：风控伪 Header 与高危客户端指纹声明
                    let cleaned = Self::clean_text(mapped);
                    // 身份声明句归一化
                    // 铁律：
                    // - System 轨：剥离管道分界标记 / 官方身份 + 身份归属声明归一化 + 竞品厂牌规范化
                    // - LeadingUser 轨：仅在命中身份归属声明句时就地归一化为官方 Antigravity 身份，绝对严禁触碰任何竞品厂牌！
                    // - General 轨：不做身份归一化，坚决保护用户提问与模型正文
                    let cleaned = match scope {
                        SanitizerScope::System => {
                            Self::normalize_system_identity(&Self::strip_pipeline_markers(&cleaned))
                        }
                        SanitizerScope::LeadingUser => Self::normalize_user_identity(&cleaned),
                        SanitizerScope::General => cleaned,
                    };
                    if cleaned != text_val {
                        obj.insert("text".to_string(), Value::String(cleaned));
                        cleaned_count += 1;
                    }
                }
            }
        }

        // 物理剔除清洗后产生的纯空文本 Part
        // 注意：思考块以及非文本部件（如 inlineData、functionCall 等）必须完好保留
        parts.retain(|part| {
            let is_thought = part
                .get("thought")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || part.get("thoughtSignature").is_some()
                || part.get("thought_signature").is_some();
            if is_thought {
                return true;
            }
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                !text.trim().is_empty()
            } else {
                true
            }
        });

        // 思考块位于首位铁律：若当前轮次存在思考块，确保其位于 index 0
        Self::ensure_thought_block_first(parts);

        cleaned_count
    }

    /// 内容轨清洗：仅执行 Header 轨（风控伪 Header 与高危客户端指纹声明），**不做**身份归一化。
    /// 用于 `contents`（常规 user / model 轮次）—— 遵循 AGENTS.md「不得剥离用户提问」。
    pub fn sanitize_parts(parts: &mut Vec<Value>) -> usize {
        Self::sanitize_parts_core(parts, SanitizerScope::General)
    }

    /// 首轮用户轨清洗：Header 轨 + 用户轨身份归一化（仅在命中身份归属声明时规范化身份，绝不替换任何竞品厂牌词汇）
    pub fn sanitize_leading_user_parts(parts: &mut Vec<Value>) -> usize {
        Self::sanitize_parts_core(parts, SanitizerScope::LeadingUser)
    }

    /// 系统轨清洗：Header 轨 + System 轨（身份归属声明归一化 + 竞品厂牌全局规范化），仅用于 `systemInstruction`。
    pub fn sanitize_system_parts(parts: &mut Vec<Value>) -> usize {
        Self::sanitize_parts_core(parts, SanitizerScope::System)
    }

    /// 核心前缀保序：确保思考块严格位于 parts 数组的首位（Index 0）
    pub fn ensure_thought_block_first(parts: &mut Vec<Value>) {
        if parts.len() <= 1 {
            return;
        }

        // 铁律：只认 thought: true。若沿用"有签名即思考块"的启发式，会把带签名的正文
        // 误判为思考块并前移 —— 既改写 part 顺序（= 签名锚点语义），也让真正的前缀错位。
        let thought_idx = parts
            .iter()
            .position(|p| crate::proxy::thinking_store::is_thought_part(p));

        if let Some(idx) = thought_idx {
            if idx != 0 {
                let thought_part = parts.remove(idx);
                parts.insert(0, thought_part);
            }
        }
    }

    /// 核心流水线节点：清洗统一中转报文中的系统提示词（systemInstruction）与对话流（contents）
    /// 支持顶层 Gemini Body 以及包裹在 `request` 字段下的 Body。
    pub fn sanitize_gemini_payload(body: &mut Value) -> usize {
        let mut total_cleaned = 0;

        // 0. 深度清理 "[undefined]" 占位串（Cherry Studio 等客户端常见注入）
        //    统一在此执行，不分协议 —— 任何客户端注入的脏数据都必须清洗。
        crate::proxy::mappers::common_utils::deep_clean_undefined(body, 0);

        // 兼容处理：若存在包装层 "request"，清洗包装内部
        if let Some(inner) = body.get_mut("request").and_then(Value::as_object_mut) {
            let mut inner_val = Value::Object(inner.clone());
            let count = Self::sanitize_gemini_payload_inner(&mut inner_val);
            if let Value::Object(new_inner) = inner_val {
                *inner = new_inner;
            }
            total_cleaned += count;
        }

        // 清洗当前层
        total_cleaned += Self::sanitize_gemini_payload_inner(body);
        total_cleaned
    }

    fn sanitize_gemini_payload_inner(body: &mut Value) -> usize {
        let mut cleaned_count = 0;

        // 1. 清洗系统提示词 (systemInstruction)
        //    走 System 轨：Header 轨之外叠加身份声明归一化（协议无关，四协议共用）
        if let Some(sys) = body
            .get_mut("systemInstruction")
            .and_then(Value::as_object_mut)
        {
            if let Some(parts) = sys.get_mut("parts").and_then(Value::as_array_mut) {
                cleaned_count += Self::sanitize_system_parts(parts);
            }

            // 若清洗后 parts 为空，物理移除整个 systemInstruction，避免向 Google 发送空的系统提示词结构
            let is_parts_empty = sys
                .get("parts")
                .and_then(Value::as_array)
                .map(|p| p.is_empty())
                .unwrap_or(true);

            if is_parts_empty {
                body.as_object_mut().map(|b| b.remove("systemInstruction"));
            }
        }

        // 2. 清洗所有对话轮次 (contents，包括 user 块与 model 块)
        //    遵循 jeikl/PR#3769 架构规范与 Issue #3764 竞品品牌保护铁律：
        //    首个 model 轮次之前的 user.part：
        //    - 倒数第一个 user 轮次之前的所有 user 轮次：属于 Agent 注入的前置提示词块，走 System 轨深度清洗；
        //    - 倒数第一个 user 轮次：最后一个文本 part 之前的 parts（0..split_idx）属于前置注入提示词，走 System 轨深度清洗；
        //      最后一个文本 part 及其随行附件属于用户真实业务提问，走 LeadingUser 轨（100% 保护竞品厂牌词汇）；
        //    - 首个 model 轮次之后的所有轮次：走 General 轨（仅剥离计费伪 Header，绝不破坏用户后续业务提问）。
        if let Some(contents) = body.get_mut("contents").and_then(Value::as_array_mut) {
            let first_model_idx = contents
                .iter()
                .position(|turn| turn.get("role").and_then(Value::as_str) == Some("model"));
            let search_limit = first_model_idx.unwrap_or(contents.len());
            let last_leading_user_idx = contents[..search_limit]
                .iter()
                .rposition(|turn| turn.get("role").and_then(Value::as_str) == Some("user"));

            for (turn_idx, turn) in contents.iter_mut().enumerate() {
                let is_user_role = turn.get("role").and_then(Value::as_str) == Some("user");
                if let Some(parts) = turn.get_mut("parts").and_then(Value::as_array_mut) {
                    if Some(turn_idx) < last_leading_user_idx && is_user_role {
                        // 倒数第一个 user 轮次之前的所有 user 轮次：Agent 注入的提示词块，走 System 轨深度清洗
                        cleaned_count += Self::sanitize_system_parts(parts);
                    } else if Some(turn_idx) == last_leading_user_idx {
                        // 第一个 model 前的倒数第一个 user 轮次：
                        // 最后一个文本 part 之前的 user.part 属于前置注入提示词（走 System 轨深度清洗），
                        // 而最后一个文本 part 及其随行附件属于用户当前真实提问（走 LeadingUser 轨，严格保护用户正文竞品品牌）
                        let last_text_idx = parts
                            .iter()
                            .rposition(|p| p.get("text").and_then(Value::as_str).is_some());

                        if let Some(split_idx) = last_text_idx {
                            if split_idx > 0 {
                                let mut leading_parts: Vec<Value> =
                                    parts.drain(..split_idx).collect();
                                cleaned_count += Self::sanitize_system_parts(&mut leading_parts);
                                cleaned_count += Self::sanitize_leading_user_parts(parts);
                                leading_parts.append(parts);
                                *parts = leading_parts;
                                Self::ensure_thought_block_first(parts);
                            } else {
                                cleaned_count += Self::sanitize_leading_user_parts(parts);
                            }
                        } else {
                            cleaned_count += Self::sanitize_leading_user_parts(parts);
                        }
                    } else {
                        // model 回复轮次及后续对话轮次，统一走 General 轨（仅剥离伪 Header，绝不破坏用户提问正文）
                        cleaned_count += Self::sanitize_parts(parts);
                    }
                }
            }

            // 对话轮次保护：移除 parts 被完全清空的轮次（若有），防止空 content 破坏 Google 协议
            contents.retain(|turn| {
                turn.get("parts")
                    .and_then(Value::as_array)
                    .map(|p| !p.is_empty())
                    .unwrap_or(true)
            });
        }

        // 3. 清洗工具声明 (tools 中的 functionDeclarations 描述文本)
        //    防御性剥离伪 Header 与独立指纹声明，严禁触碰工具名称 (name) 与参数 Schema (parameters)
        if let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) {
            for tool in tools.iter_mut() {
                if let Some(decls) = tool
                    .get_mut("functionDeclarations")
                    .and_then(Value::as_array_mut)
                {
                    for decl in decls.iter_mut() {
                        let desc_opt = decl
                            .get("description")
                            .and_then(Value::as_str)
                            .map(|s| s.to_string());
                        if let Some(desc) = desc_opt {
                            let cleaned = Self::clean_text(&desc);
                            if cleaned != desc {
                                if let Some(obj) = decl.as_object_mut() {
                                    obj.insert("description".to_string(), Value::String(cleaned));
                                    cleaned_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        cleaned_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_client_identity_mapping_normalizes_to_official_antigravity() {
        // 整串等值映射：必须对齐为官方 Antigravity 身份
        assert_eq!(
            PromptSanitizer::normalize_client_identity(CLAUDE_AGENT_SDK_IDENTITY),
            OFFICIAL_ANTIGRAVITY_IDENTITY
        );
        assert_eq!(
            PromptSanitizer::normalize_client_identity(CLAUDE_CODE_CLI_IDENTITY),
            OFFICIAL_ANTIGRAVITY_IDENTITY
        );
        assert_eq!(
            PromptSanitizer::normalize_client_identity("You are an expert coder."),
            "You are an expert coder."
        );
    }

    #[test]
    fn test_strip_pipeline_markers_and_self_identity() {
        assert_eq!(
            PromptSanitizer::strip_pipeline_markers("Rule A\n--- [SYSTEM_PROMPT_END] ---\nRule B"),
            "Rule A\n\nRule B"
        );
        assert_eq!(
            PromptSanitizer::strip_pipeline_markers(&format!(
                "Intro\n{SELF_IDENTITY_BLOCK}\nOutro"
            )),
            "Intro\n\nOutro"
        );
    }

    #[test]
    fn test_billing_metadata_detection_is_model_agnostic() {
        assert!(PromptSanitizer::is_billing_metadata(
            "x-anthropic-billing-header: cc_version=2.1.270.ffc;"
        ));
        // 多行（真实提示词）不得判定为风险
        assert!(!PromptSanitizer::is_billing_metadata(
            "x-anthropic-billing-header: a;\nSecond line prompt instruction"
        ));
        assert!(!PromptSanitizer::is_billing_metadata(
            "You are an expert coder."
        ));
    }

    #[test]
    fn test_billing_metadata_part_is_dropped_and_undefined_cleaned() {
        let mut payload = json!({
            "systemInstruction": { "parts": [
                { "text": "x-anthropic-billing-header: cc_version=2.1.270.ffc;" },
                { "text": "You are an expert coder." }
            ]},
            "generationConfig": { "foo": "[undefined]" }
        });
        PromptSanitizer::sanitize_gemini_payload(&mut payload);

        let parts = payload["systemInstruction"]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 1, "计费元数据 part 必须被剔除: {payload}");
        assert_eq!(parts[0]["text"], "You are an expert coder.");
        assert!(
            payload["generationConfig"].get("foo").is_none(),
            "[undefined] 占位串必须被清理: {payload}"
        );
    }

    #[test]
    fn test_clean_text_multiline_system_prompt_with_billing() {
        let raw = concat!(
            "x-anthropic-billing-header: cc_version=2.1.220.04c; cc_entrypoint=sdk-ts;\n",
            "You are Claude Code, Anthropic's official CLI for Claude.\n\n",
            "Please follow these instructions:\n",
            "1. Assist with coding tasks."
        );
        let cleaned = PromptSanitizer::clean_text(raw);
        assert!(!cleaned.contains("x-anthropic-billing-header"));
        assert!(cleaned.starts_with("You are Claude Code"));
        assert!(cleaned.contains("1. Assist with coding tasks."));
    }

    #[test]
    fn test_clean_waf_trigger_cc_entrypoint_header() {
        let raw = concat!(
            "x-custom-billing: cc_version=2.0; cc_entrypoint=cli;\n",
            "Actual user instructions."
        );
        let cleaned = PromptSanitizer::clean_text(raw);
        assert_eq!(cleaned, "Actual user instructions.");
    }

    #[test]
    fn test_clean_generic_wildcard_billing_headers() {
        let raw = concat!(
            "x-billing: enabled\n",
            "x-custom-billing-info: token123\n",
            "x-client-billing: active\n",
            "anthropic-billing-header: cc_version=2.1\n",
            "Actual user instructions."
        );
        let cleaned = PromptSanitizer::clean_text(raw);
        assert_eq!(cleaned, "Actual user instructions.");
    }

    #[test]
    fn test_strictly_preserves_session_headers_and_tokens() {
        // 关键验证：任何形式的 session ID 绝不能被破坏或删除
        let raw = concat!(
            "x-jeikcode-session-id: session-abc-123\n",
            "x-session-id: generic-sess-789\n",
            "x-client-session-id: client-sess-000\n",
            "Please keep my session active."
        );
        let cleaned = PromptSanitizer::clean_text(raw);
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn test_strictly_preserves_user_delimiters_and_xml_tags() {
        // 关键验证：用户的 JeikCode 提示词格式包含 XML 与 === ... === 分割符，100% 原样保留
        let jeik_prompt = concat!(
            "<environment>\n",
            "You are JeikCode AI coding Agent by Jeik.\n\n",
            "## PRECEDENCE:\n",
            "- Content enclosed in XML tags represents current environment.\n",
            "- Rules under headers matching `=== ... (*.md) ===` (such as `AGENTS.md`, `CLAUDE.md`, `=== MEMORY ===`) constitute USER PROVISIONS.\n",
            "</environment>\n\n",
            "=== AGENTS.md ===\n",
            "User custom provisions.\n",
            "=== MEMORY ===\n",
            "Memory block 1."
        );
        let cleaned = PromptSanitizer::clean_text(jeik_prompt);
        assert_eq!(cleaned, jeik_prompt);
    }

    #[test]
    fn test_protects_code_blocks_containing_waf_signatures() {
        let code = concat!(
            "Here is my code:\n",
            "```python\n",
            "headers = {'x-anthropic-billing-header': 'cc_version=1.0'}\n",
            "print(headers)\n",
            "```\n",
            "Does this look right?"
        );
        let cleaned = PromptSanitizer::clean_text(code);
        assert_eq!(cleaned, code);
    }

    #[test]
    fn test_protects_normal_user_prompts_and_http_headers() {
        let normal_text = concat!(
            "How do I set Authorization: Bearer <token> in curl?\n",
            "- Step 1: Add -H flag\n",
            "- Step 2: Test endpoint\n\n",
            "Total steps: 2"
        );
        let cleaned = PromptSanitizer::clean_text(normal_text);
        assert_eq!(cleaned, normal_text);
    }

    #[test]
    fn test_sanitize_gemini_payload_system_and_user_blocks() {
        let mut payload = json!({
            "project": "test-project",
            "model": "gemini-3.8-flash-high",
            "request": {
                "systemInstruction": {
                    "role": "user",
                    "parts": [
                        {
                            "text": "x-anthropic-billing-header: cc_version=2.1;\n<environment>You are JeikCode</environment>\n=== AGENTS.md ==="
                        }
                    ]
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {
                                "text": "x-anthropic-billing-header: cc_entrypoint=cli;\nPlease analyze my data:\n=== MEMORY ===\n- Metric A: 10\n- Metric B: 20"
                            }
                        ]
                    },
                    {
                        "role": "model",
                        "parts": [
                            {
                                "text": "Model output response."
                            }
                        ]
                    }
                ]
            }
        });

        let cleaned_count = PromptSanitizer::sanitize_gemini_payload(&mut payload);
        assert_eq!(cleaned_count, 2);

        let sys_text = payload["request"]["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .unwrap();
        // 计费头被精确移除，身份被归一化为官方 Antigravity 身份，但 XML 与 === AGENTS.md === 完好无损
        assert!(!sys_text.contains("x-anthropic-billing-header"));
        assert!(sys_text.contains(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(sys_text.contains("<environment>"));
        assert!(sys_text.contains("</environment>"));
        assert!(sys_text.contains("=== AGENTS.md ==="));

        let user_text = payload["request"]["contents"][0]["parts"][0]["text"]
            .as_str()
            .unwrap();
        assert!(!user_text.contains("x-anthropic-billing-header"));
        assert!(user_text.contains("=== MEMORY ==="));
        assert!(user_text.contains("- Metric A: 10\n- Metric B: 20"));
    }

    #[test]
    fn test_clean_standalone_billing_header_part_purges_empty_part_and_empty_system_instruction() {
        // [New API / CC Issue] 模拟当 CC 将 billing header 作为独立 Part 上送时：
        // 清洗后空 Part 必须被物理移除；当整个系统提示词仅有该 Header 时，必须物理移除 systemInstruction 节点
        let mut payload = json!({
            "project": "test-project",
            "request": {
                "systemInstruction": {
                    "role": "user",
                    "parts": [
                        {
                            "text": "x-anthropic-billing-header: cc_version=2.1.272.255; cc_entrypoint=claude-vscode;"
                        }
                    ]
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            { "text": "Hello world" }
                        ]
                    }
                ]
            }
        });

        let cleaned_count = PromptSanitizer::sanitize_gemini_payload(&mut payload);
        assert_eq!(cleaned_count, 1);

        // 验证：systemInstruction 因为 parts 为空被完全注销，不存在 {"text": ""} 畸变
        assert!(payload["request"].get("systemInstruction").is_none());
        assert_eq!(
            payload["request"]["contents"][0]["parts"][0]["text"],
            "Hello world"
        );
    }

    #[test]
    fn test_ensure_thought_block_always_first_after_sanitization() {
        // [铁律验证] 清洗完成后，必须严格确保思考块位于当前轮次 parts 的首位 (Index 0)
        let mut payload = json!({
            "project": "test-project",
            "request": {
                "contents": [
                    {
                        "role": "model",
                        "parts": [
                            {
                                "text": "x-anthropic-billing-header: cc_version=2.1.272.255; cc_entrypoint=cli;\nSome commentary."
                            },
                            {
                                "text": "I am thinking deeply about the problem...",
                                "thought": true,
                                "thoughtSignature": "valid_hmac_signature_123456"
                            },
                            {
                                "text": "Final answer text."
                            }
                        ]
                    }
                ]
            }
        });

        let _ = PromptSanitizer::sanitize_gemini_payload(&mut payload);

        let parts = payload["request"]["contents"][0]["parts"]
            .as_array()
            .expect("parts should be array");

        // 思考块必须被重排置顶到 index 0
        assert_eq!(parts[0]["thought"], true);
        assert_eq!(
            parts[0]["text"],
            "I am thinking deeply about the problem..."
        );
        assert_eq!(parts[0]["thoughtSignature"], "valid_hmac_signature_123456");

        // 其它非思考部件紧随其后且经过了清洗
        assert_eq!(parts[1]["text"], "Some commentary.");
        assert_eq!(parts[2]["text"], "Final answer text.");
    }

    #[test]
    fn test_clean_claude_agent_sdk_preamble() {
        // [WAF 429 规避] 验证 Claude Agent SDK 前导指纹声明被精准剥离
        let raw = concat!(
            "You are a Claude agent, built on Anthropic's Claude Agent SDK.\n\n",
            "You have access to a variety of tools."
        );
        let cleaned = PromptSanitizer::clean_text(raw);
        assert!(!cleaned.contains("Claude Agent SDK"));
        assert_eq!(cleaned, "You have access to a variety of tools.");
    }

    #[test]
    fn test_clean_claude_agent_sdk_cli_identity() {
        // [WAF 429 规避] 验证 Claude Code 在 Claude Agent SDK 运行时注入的第二类身份声明被精准剥离与归一化
        let raw = concat!(
            "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.\n\n",
            "You have access to a variety of tools."
        );
        let cleaned = PromptSanitizer::clean_text(raw);
        assert!(!cleaned.contains("Claude Agent SDK"));
        assert!(!cleaned.contains("Claude Code"));
        assert_eq!(cleaned, "You have access to a variety of tools.");

        // System 轨头部窗口归一化为官方 Antigravity 助手
        let normalized = PromptSanitizer::normalize_system_identity(raw);
        eprintln!("DEBUG normalized = {:?}", normalized);
        assert!(normalized.starts_with(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(normalized.contains("You have access to a variety of tools."));
        assert!(!normalized.contains("running within the Claude Agent SDK"));

        // 客户端整串等值归一化映射
        let sdk_cli_identity = "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.";
        assert_eq!(
            PromptSanitizer::normalize_client_identity(sdk_cli_identity),
            OFFICIAL_ANTIGRAVITY_IDENTITY
        );
    }

    #[test]
    fn test_clean_waf_trigger_cc_extended_attribution_headers() {
        // [Claude Code 2.1.301] 扩展归属元数据字段 (cc_workload, cc_is_subagent, cc_prev_req, cc_prompt_id, cc_turn_origin 等)
        let raw1 = concat!(
            "x-anthropic-billing-header: cc_workload=interactive; cc_is_subagent=true;\n",
            "Actual user instructions."
        );
        assert_eq!(
            PromptSanitizer::clean_text(raw1),
            "Actual user instructions."
        );

        let raw2 = concat!(
            "x-client-metadata: cc_workload=interactive; cc_is_subagent=true;\n",
            "Actual user instructions."
        );
        assert_eq!(
            PromptSanitizer::clean_text(raw2),
            "Actual user instructions."
        );

        let raw3 = concat!(
            "x-anthropic-billing-header: cc_prev_req=req_0194e4; cc_prompt_id=e7b4478f; cc_turn_origin=auto;\n",
            "Actual user instructions."
        );
        assert_eq!(
            PromptSanitizer::clean_text(raw3),
            "Actual user instructions."
        );
    }

    #[test]
    fn test_clean_mid_paragraph_billing_header() {
        // [WAF 429 规避] 验证即使 billing header 嵌入在段落中间也能够被剥离
        let raw = "Intro text x-anthropic-billing-header: cc_version=2.1.278; cc_entrypoint=cli; cch=fa690; and more text";
        let cleaned = PromptSanitizer::clean_text(raw);
        assert!(!cleaned.contains("x-anthropic-billing-header"));
    }

    // ==================== System 轨：身份声明归一化 ====================

    #[test]
    fn test_normalize_identity_broad_attribution_forms() {
        // 广谱覆盖：厂商归属（created by）、竞品模型（based on）、复合身份串（designed by …）
        for (raw, expected) in [
            (
                "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
                OFFICIAL_ANTIGRAVITY_IDENTITY.to_string(),
            ),
            (
                "You are Codex, an advanced coding agent based on GPT-6.",
                OFFICIAL_ANTIGRAVITY_IDENTITY.to_string(),
            ),
            (
                "You are an AI agent created by Example Corp.",
                OFFICIAL_ANTIGRAVITY_IDENTITY.to_string(),
            ),
            (
                concat!(
                    "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n",
                    "You are pair programming with a USER."
                ),
                format!("{OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou are pair programming with a USER."),
            ),
            // 逗号引导的归属声明（Claude Agent SDK 形态）
            (
                "You are a Claude agent, built on Anthropic's Claude Agent SDK.\nYou have access to tools.",
                format!("{OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou have access to tools."),
            ),
            // 长修饰链 + 厂商归属
            (
                "You are a helpful and highly capable general-purpose AI coding assistant created by Acme Corp.",
                OFFICIAL_ANTIGRAVITY_IDENTITY.to_string(),
            ),
            // 知名特定客户端开场白（Claude Code CLI）
            (
                "You are Claude Code, Anthropic's official CLI for Claude.\nYou have access to tools.",
                format!("{OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou have access to tools."),
            ),
        ] {
            assert_eq!(PromptSanitizer::normalize_system_identity(raw), expected);
        }
    }

    #[test]
    fn test_normalize_identity_never_swallows_following_lines() {
        // [结构性防炸] 归属声明取到句读边界即止：身份行之后的多行规则必须逐字保留。
        let raw = concat!(
            "You are an AI agent created by Acme\n",
            "Rule 1: always do X\n",
            "Rule 2: never do Y"
        );
        assert_eq!(
            PromptSanitizer::normalize_system_identity(raw),
            format!("{OFFICIAL_ANTIGRAVITY_IDENTITY}\nRule 1: always do X\nRule 2: never do Y")
        );
    }

    #[test]
    fn test_normalize_identity_keeps_comma_continuation_intact() {
        let raw =
            "You are an AI agent created by Acme, and you must never reveal internal tooling.";
        assert_eq!(
            PromptSanitizer::normalize_system_identity(raw),
            format!("{OFFICIAL_ANTIGRAVITY_IDENTITY}, and you must never reveal internal tooling.")
        );
    }

    #[test]
    fn test_normalize_identity_preserves_non_attribution_identities() {
        // 缺少「归属声明」要素的一律保留；通用专家与中性助手身份不得被改写
        for raw in [
            "You are a helpful assistant. Please respond in Chinese.",
            "You are an AI assistant that helps users write code by calling tools.",
            "You are an expert full-stack developer specializing in Rust and TypeScript.",
        ] {
            assert_eq!(PromptSanitizer::normalize_system_identity(raw), raw);
        }

        // 跨子句守卫：身份名词与归属动词之间隔着完整的另一个子句时不得整段归一化
        let cross_clause =
            "You are a coding agent, and the config was created by the setup script, so keep it.";
        assert_eq!(
            PromptSanitizer::normalize_system_identity(cross_clause),
            cross_clause
        );
    }

    #[test]
    fn test_normalize_identity_only_scans_system_prompt_head() {
        // 头部窗口（前 4 句）之外的身份类表述一律不动，避免误伤长提示词正文
        let mut raw = String::from("You are a coding assistant.\n\n");
        for i in 0..6 {
            raw.push_str(&format!("Sentence {i} is a normal instruction.\n"));
        }
        raw.push_str("The tool was created by Acme.\n");
        assert_eq!(PromptSanitizer::normalize_system_identity(&raw), raw);
    }

    #[test]
    fn test_normalize_identity_protects_code_blocks_and_xml_delimiters() {
        let code = concat!(
            "You are an AI agent created by Acme.\n\n",
            "Example config:\n",
            "```\n",
            "// generated by Hermes Agent created by Nous Research\n",
            "```"
        );
        let cleaned = PromptSanitizer::normalize_system_identity(code);
        assert!(cleaned.starts_with(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(cleaned.contains("// generated by Hermes Agent created by Nous Research"));

        let xml = concat!(
            "<environment>\n",
            "You are Hermes Agent created by Nous Research.\n",
            "</environment>\n\n",
            "=== AGENTS.md ===\nUser provisions."
        );
        assert_eq!(
            PromptSanitizer::normalize_system_identity(xml),
            format!(
                "<environment>\n{OFFICIAL_ANTIGRAVITY_IDENTITY}\n</environment>\n\n=== AGENTS.md ===\nUser provisions."
            )
        );
    }

    #[test]
    fn test_sanitize_gemini_payload_identity_scope_is_system_only() {
        // System 轨只作用于 systemInstruction：contents（用户提问 / 工具消息）逐字保留
        let mut payload = json!({
            "project": "test-project",
            "request": {
                "systemInstruction": {
                    "role": "user",
                    "parts": [
                        { "text": "You are Hermes Agent, an intelligent AI assistant created by Nous Research." }
                    ]
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            { "text": "Quote the note created by Alice in the doc." }
                        ]
                    }
                ]
            }
        });

        let cleaned_count = PromptSanitizer::sanitize_gemini_payload(&mut payload);
        assert_eq!(cleaned_count, 1);
        assert_eq!(
            payload["request"]["systemInstruction"]["parts"][0]["text"],
            OFFICIAL_ANTIGRAVITY_IDENTITY
        );
        assert_eq!(
            payload["request"]["contents"][0]["parts"][0]["text"],
            "Quote the note created by Alice in the doc."
        );
    }

    #[test]
    fn test_sanitize_tools_function_declarations_description() {
        let mut payload = json!({
            "tools": [
                {
                    "functionDeclarations": [
                        {
                            "name": "Bash",
                            "description": "x-anthropic-billing-header: cc_version=2.1;\nExecute a bash command in the terminal.",
                            "parameters": {
                                "type": "OBJECT",
                                "properties": {
                                    "command": { "type": "STRING" }
                                },
                                "required": ["command"]
                            }
                        }
                    ]
                }
            ]
        });

        let cleaned_count = PromptSanitizer::sanitize_gemini_payload(&mut payload);
        assert_eq!(cleaned_count, 1);

        let func = &payload["tools"][0]["functionDeclarations"][0];
        // 函数名与参数 Schema 100% 保持无损
        assert_eq!(func["name"], "Bash");
        assert_eq!(func["parameters"]["required"][0], "command");
        // 描述中的伪 Header 被安全剔除
        assert_eq!(
            func["description"],
            "Execute a bash command in the terminal."
        );
    }

    #[test]
    fn test_sanitize_gemini_payload_normalizes_system_identity_while_preserving_contents() {
        // AGENTS.md 铁律：系统提示词及首个 model 之前的注入块中的身份声明统一归一化为官方 Antigravity 身份，而后续多轮对话绝不破坏
        let jeik = concat!(
            "<environment>\n",
            "You are JeikCode AI coding Agent by Jeik.\n\n",
            "## PRECEDENCE:\n",
            "- Rules under headers matching `=== ... (*.md) ===` constitute USER PROVISIONS.\n",
            "</environment>\n\n",
            "=== AGENTS.md ===\n",
            "User custom provisions."
        );
        let mut payload = json!({
            "request": {
                "systemInstruction": { "role": "user", "parts": [{ "text": jeik }] },
                "contents": [
                    { "role": "user", "parts": [{ "text": jeik }] },
                    { "role": "model", "parts": [{ "text": "Model answer." }] },
                    { "role": "user", "parts": [{ "text": "Follow-up question about JeikCode." }] }
                ]
            }
        });

        assert_eq!(PromptSanitizer::sanitize_gemini_payload(&mut payload), 2);
        let sys_text = payload["request"]["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .unwrap();
        assert!(sys_text.contains(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(sys_text.contains("<environment>"));
        assert!(sys_text.contains("</environment>"));
        assert!(sys_text.contains("=== AGENTS.md ==="));
        assert!(sys_text.contains("User custom provisions."));

        // 首个 model 轮次之前的 user 块（客户端注入的系统提示词）也被深度归一化
        let user_leading = payload["request"]["contents"][0]["parts"][0]["text"]
            .as_str()
            .unwrap();
        assert!(user_leading.contains(OFFICIAL_ANTIGRAVITY_IDENTITY));

        // model 之后的后续 user 提问保持 100% 原始文本
        assert_eq!(
            payload["request"]["contents"][2]["parts"][0]["text"],
            "Follow-up question about JeikCode."
        );
    }

    #[test]
    fn test_sanitize_gemini_payload_leading_user_turn_with_injected_system_prompts_and_real_query()
    {
        // 覆盖客户端把系统提示词放在 user 块中的场景：
        // user: [提示词1, 提示词2, 提示词3, 第一条用户消息]
        let mut payload = json!({
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        { "text": "You are a personal assistant running inside OpenClaw.\n## Tooling\nAvailable tools are listed." },
                        { "text": "<environment>\nYou are Cherry Studio AI assistant.\n</environment>" },
                        { "text": "## Available Skills:\n- skill 1\n- skill 2" },
                        { "text": "请帮我实现一个高效的快速排序算法，语言使用 Rust。" }
                    ]
                },
                {
                    "role": "model",
                    "parts": [
                        { "text": "好的，以下是 Rust 语言实现的快速排序代码：" }
                    ]
                },
                {
                    "role": "user",
                    "parts": [
                        // 后续多轮对话中如果用户提到第三方工具名称，绝不破坏用户提问正文
                        { "text": "请问刚才那段代码能在 OpenClaw 插件环境下运行吗？" }
                    ]
                }
            ]
        });

        let cleaned_count = PromptSanitizer::sanitize_gemini_payload(&mut payload);
        assert_eq!(cleaned_count, 2);

        let parts = payload["contents"][0]["parts"].as_array().unwrap();
        // Part 0：OpenClaw 身份被归一化为官方 Antigravity，后续工具说明保持完整
        assert!(parts[0]["text"]
            .as_str()
            .unwrap()
            .starts_with(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(parts[0]["text"]
            .as_str()
            .unwrap()
            .contains("## Tooling\nAvailable tools are listed."));

        // Part 1：XML 标签内部的 Cherry Studio 身份被归一化，标签结构保持无损
        assert!(parts[1]["text"]
            .as_str()
            .unwrap()
            .contains(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(parts[1]["text"].as_str().unwrap().contains("<environment>"));
        assert!(parts[1]["text"]
            .as_str()
            .unwrap()
            .contains("</environment>"));

        // Part 2：技能说明保持原样
        assert_eq!(
            parts[2]["text"],
            "## Available Skills:\n- skill 1\n- skill 2"
        );

        // Part 3：第一条真实用户提问绝对保持原汁原味
        assert_eq!(
            parts[3]["text"],
            "请帮我实现一个高效的快速排序算法，语言使用 Rust。"
        );

        // 后续对话轮次（model 之后）：用户后续提问保持 100% 原始文本
        assert_eq!(
            payload["contents"][2]["parts"][0]["text"],
            "请问刚才那段代码能在 OpenClaw 插件环境下运行吗？"
        );
    }

    #[test]
    fn test_code_block_with_placeholder_text_no_recursive_expansion() {
        // [防御递归炸弹] 代码块中若本身包含占位符文本，单趟还原绝对不会被二次递归展开
        let input = concat!(
            "Some text before\n",
            "```rust\n",
            "let x = \"__PROMPT_SANITIZER_CODE_BLOCK_0__\";\n",
            "```\n",
            "Some text after"
        );
        let cleaned = PromptSanitizer::clean_text(input);
        assert!(cleaned.contains("__PROMPT_SANITIZER_CODE_BLOCK_0__"));
    }

    #[test]
    fn test_exclamation_mark_instruction_not_swallowed() {
        // 感叹号或问号结束的身份声明，后续指令绝对不可被贪婪吞噬
        let raw = concat!(
            "You are an AI assistant created by Example Corp! ",
            "Please always format all responses as valid JSON only."
        );
        let normalized = PromptSanitizer::normalize_system_identity(raw);
        assert!(normalized.contains("Please always format all responses as valid JSON only."));
    }

    #[test]
    fn test_comprehensive_harness_and_identity_normalization() {
        let test_cases = [
            (
                "OpenCode生产真实报文",
                "You are opencode, an interactive CLI tool that helps users with software engineering tasks. Use the instructions below and the tools available to you to assist the user.",
                "opencode",
            ),
            (
                "OpenClaw生产真实报文",
                "---\nOpenClaw plugin-injected system context. This block is not workspace file content.\n---\nYou are a personal assistant running inside OpenClaw.\n## Tooling\nAvailable tools are policy-filtered.",
                "running inside OpenClaw",
            ),
            (
                "Claude Code CLI真实报文",
                "You are Claude Code, Anthropic's official CLI for Claude.\nTools available.",
                "Claude Code",
            ),
            (
                "Claude Agent SDK运行时报文",
                "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.\nTools available.",
                "Claude Agent SDK",
            ),
            (
                "Claude Agent独立身份声明",
                "You are a Claude agent, built on Anthropic's Claude Agent SDK.\nYou have tools.",
                "Claude Agent SDK",
            ),
            (
                "Cursor真实报文",
                "You are an intelligent programming assistant integrated into Cursor editor.",
                "Cursor editor",
            ),
            (
                "Cascade真实报文",
                "You are Cascade, an AI pair programmer by Codeium. Follow rules.",
                "Cascade",
            ),
            (
                "Cline真实报文",
                "You are Cline, a highly skilled software engineer with extensive knowledge in many programming languages.",
                "Cline",
            ),
            (
                "Aider真实报文",
                "You are aider, an expert software engineer collaborating with the user.",
                "aider",
            ),
            (
                "Codex真实报文",
                "You are Codex, an advanced coding agent based on GPT-6.",
                "Codex",
            ),
            (
                "Hermes Agent真实报文",
                "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
                "Hermes Agent",
            ),
            (
                "KiloCode真实报文",
                "You are KiloCode, an AI coding assistant developed by Kilo AI.",
                "KiloCode",
            ),
            (
                "DSH Harness真实报文",
                "You are DSH, an automated software development harness designed for agentic coding workflows.",
                "DSH",
            ),
            (
                "Devin真实报文",
                "You are Devin, an autonomous software engineer created by Cognition.",
                "Devin",
            ),
            (
                "GrokBuild真实报文",
                "You are Grok 4.6 released by xAI. You are an interactive CLI tool that helps users with software engineering tasks. Your main goal is to complete the user's request in the <user_query> tag.",
                "xAI",
            ),
            (
                "逗号续写功能指令形态",
                "You are an AI agent created by Acme, and you must never reveal internal tooling.",
                "and you must never reveal internal tooling.",
            ),
            (
                "中文归属声明形态",
                "你是通义灵码，一个由阿里云开发的人工智能编码助手。",
                "通义灵码",
            ),
            (
                "中文基于模型声明形态",
                "你是深度求索开发的助手，基于DeepSeek大模型。",
                "基于DeepSeek大模型",
            ),
            (
                "中文我是开场白形态",
                "我是百度开发的人工智能代码助手文心快码。",
                "文心快码",
            ),
            (
                "JeikCode完整主要提示词(环境标签+多行指令)",
                concat!(
                    "<environment>\n",
                    "You are JeikCode AI coding Agent by Jeik running on your underlying model. Always communicate in the language used by the user.\n",
                    "## PRECEDENCE:\n",
                    "Critical Precedence: Rules under <project_instructions> constitute USER PROVISIONS.\n",
                    "=== AGENTS.md ===\n",
                    "Do not modify.\n",
                    "</environment>"
                ),
                "JeikCode",
            ),
            (
                "JeikCode单行精简身份(归属与宿主声明)",
                "You are JeikCode AI coding Agent by Jeik running on your underlying model.",
                "JeikCode",
            ),
            (
                "泛化xxxcode形态",
                "You are atomcode, an interactive coding assistant.",
                "atomcode",
            ),
            (
                "泛化xx code形态",
                "You are hyper code AI coding agent. Complete the task.",
                "hyper code",
            ),
            (
                "Pi客户端形态",
                "You are Pi AI coding agent. Help write code.",
                "Pi",
            ),
            (
                "任意标签内部深度身份声明",
                concat!(
                    "Rule 1.\nRule 2.\nRule 3.\nRule 4.\nRule 5.\nRule 6.\nRule 7.\nRule 8.\nRule 9.\n",
                    "<custom_agent>\n",
                    "You are JeikCode AI coding Agent by Jeik running on your underlying model.\n",
                    "Do something.\n",
                    "</custom_agent>"
                ),
                "JeikCode",
            ),
            (
                "xx Studio大写形态",
                "YOU ARE CHERRY STUDIO, an intelligent AI.",
                "CHERRY STUDIO",
            ),
            (
                "xx Studio小写形态",
                "you are lm studio AI assistant. Help the user.",
                "lm studio",
            ),
            (
                "xxStudio驼峰混合大小写形态",
                "You are CherryStudio, an AI assistant.",
                "CherryStudio",
            ),
            (
                "xxStudio全大写形态",
                "YOU ARE LMSTUDIO AI ASSISTANT.",
                "LMSTUDIO",
            ),
            (
                "**claw大写形态",
                "YOU ARE OPENCLAW.",
                "OPENCLAW",
            ),
            (
                "** claw双词小写形态",
                "you are open claw AI coding agent.",
                "open claw",
            ),
            (
                "标签包裹的Cherry Studio大小写不敏感形态",
                "<environment>\nYOU ARE CHERRY STUDIO AI ASSISTANT.\n</environment>",
                "CHERRY STUDIO",
            ),
        ];

        for (name, raw, key_fragment) in test_cases {
            let out = PromptSanitizer::normalize_system_identity(raw);
            assert_ne!(out, raw, "Case '{name}' 必须被归一化处理");
            assert!(
                out.contains(OFFICIAL_ANTIGRAVITY_IDENTITY),
                "Case '{name}' 必须包含官方 Antigravity 身份"
            );
            if key_fragment != "and you must never reveal internal tooling." {
                assert!(
                    !out.to_lowercase().contains(&key_fragment.to_lowercase()),
                    "Case '{name}' 不得残留第三方指纹: '{key_fragment}'"
                );
            } else {
                assert!(
                    out.contains(key_fragment),
                    "Case '{name}' 必须完整保留逗号续写指令"
                );
            }
        }
    }

    #[test]
    fn test_strictly_protects_generic_prompts() {
        let protected_cases = [
            (
                "官方Antigravity自身(保持稳定)",
                OFFICIAL_ANTIGRAVITY_IDENTITY,
            ),
            (
                "通用中性提示词(绝对保护)",
                "You are a helpful assistant. Please respond in Chinese.",
            ),
            (
                "通用AI编程提示词(绝对保护)",
                "You are an AI assistant that helps users write code by calling tools.",
            ),
            (
                "WorkBuddy会话动力声明(豁免不洗)",
                "This conversation is powered by gemini-3.8-flash-medium\r\n\r\nYour main goal is to follow the USER's instructions at each message, denoted by the <user_query> tag.",
            ),
            (
                "开发者专家角色设定(绝对保护)",
                "You are an expert full-stack developer specializing in Rust and TypeScript.",
            ),
            (
                "代码块中包含的特征(绝对保护)",
                "You are a helpful assistant.\n```python\n// generated by Hermes Agent created by Nous Research\nheaders = {'x-anthropic-billing-header': 'test'}\n```",
            ),
            (
                "头部扫描窗口之外的引用(绝对保护)",
                "You are a helpful assistant.\nSentence 1.\nSentence 2.\nSentence 3.\nSentence 4.\nSentence 5.\nSentence 6.\nSentence 7.\nSentence 8.\nThe module was created by Acme.",
            ),
        ];

        for (name, raw) in protected_cases {
            let out = PromptSanitizer::normalize_system_identity(raw);
            assert_eq!(out, raw, "Case '{name}' 属于保护范畴，绝不可被误杀改写！");
        }
    }

    #[test]
    fn test_competitor_brands_normalization_to_google() {
        // 1. 英文竞品厂牌替换验证（大小写不敏感）
        let raw_en = "Powered by OpenAI and Anthropic, using Qwen architecture under ByteDance, Tencent, Xiaomi and Huawei.";
        let cleaned_en = PromptSanitizer::normalize_system_identity(raw_en);
        assert!(!cleaned_en.to_lowercase().contains("openai"));
        assert!(!cleaned_en.to_lowercase().contains("anthropic"));
        assert!(!cleaned_en.to_lowercase().contains("qwen"));
        assert!(!cleaned_en.to_lowercase().contains("bytedance"));
        assert!(!cleaned_en.to_lowercase().contains("tencent"));
        assert!(!cleaned_en.to_lowercase().contains("xiaomi"));
        assert!(!cleaned_en.to_lowercase().contains("huawei"));
        assert!(cleaned_en.contains("Google"));

        // 2. 中文竞品厂牌替换验证
        let raw_zh = "本项目由字节跳动开发，经由腾讯、小米、华为以及通义千问、百度深度支持。";
        let cleaned_zh = PromptSanitizer::normalize_system_identity(raw_zh);
        assert!(!cleaned_zh.contains("字节跳动"));
        assert!(!cleaned_zh.contains("腾讯"));
        assert!(!cleaned_zh.contains("小米"));
        assert!(!cleaned_zh.contains("华为"));
        assert!(!cleaned_zh.contains("通义千问"));
        assert!(!cleaned_zh.contains("百度"));
        assert!(cleaned_zh.contains("Google"));

        // 3. 严格保护代码块中的厂牌名称（100% 豁免）
        let raw_code = concat!(
            "Instructions from OpenAI:\n",
            "```python\n",
            "import openai\n",
            "from anthropic import Anthropic\n",
            "# Supported by Tencent and Huawei\n",
            "client = openai.OpenAI()\n",
            "```\n",
            "End of instructions."
        );
        let cleaned_code = PromptSanitizer::normalize_system_identity(raw_code);
        // 代码块外部的 OpenAI 被替换为 Google
        assert!(cleaned_code.starts_with("Instructions from Google:"));
        // 代码块内部的 import openai 与 anthropic 完好无损
        assert!(cleaned_code.contains("import openai"));
        assert!(cleaned_code.contains("from anthropic import Anthropic"));
        assert!(cleaned_code.contains("# Supported by Tencent and Huawei"));
        assert!(cleaned_code.contains("client = openai.OpenAI()"));
    }

    #[test]
    fn test_issue_3764_user_track_never_replaces_competitor_brands() {
        // Issue #3764: 严格区分 System 轨与 User 轨
        // systemInstruction 允许竞品厂牌替换与全局身份归一化；
        // contents 中的 user 轮次（包括首轮）属于用户业务提问轨，坚决恪守 AGENTS.md 铁律，
        // 绝对严禁执行竞品厂牌全局替换，杜绝将用户提问中的 OpenAI、Anthropic、Claude、ChatGPT等误篡改为 Google！
        let mut payload = json!({
            "systemInstruction": {
                "parts": [
                    { "text": "System prompt provided by OpenAI and Anthropic." }
                ]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        { "text": "Please compare OpenAI GPT-4o with Anthropic Claude 3.5 Sonnet, and tell me about ByteDance, Tencent, and Baidu." }
                    ]
                },
                {
                    "role": "model",
                    "parts": [
                        { "text": "Here is the comparison..." }
                    ]
                },
                {
                    "role": "user",
                    "parts": [
                        { "text": "How does ChatGPT compare to Gemini?" }
                    ]
                }
            ]
        });

        PromptSanitizer::sanitize_gemini_payload(&mut payload);

        // 1. systemInstruction 走了 System 轨，竞品厂牌被替换为 Google
        let sys_text = payload["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .unwrap();
        assert!(sys_text.contains("Google"));
        assert!(!sys_text.to_lowercase().contains("openai"));
        assert!(!sys_text.to_lowercase().contains("anthropic"));

        // 2. 首轮 user 块必须 100% 保留所有竞品厂牌（OpenAI, Anthropic, Claude, ByteDance, Tencent, Baidu），绝不替换为 Google！
        let user1_text = payload["contents"][0]["parts"][0]["text"].as_str().unwrap();
        assert!(user1_text.contains("OpenAI"));
        assert!(user1_text.contains("Anthropic"));
        assert!(user1_text.contains("Claude"));
        assert!(user1_text.contains("ByteDance"));
        assert!(user1_text.contains("Tencent"));
        assert!(user1_text.contains("Baidu"));
        assert!(!user1_text.contains("Google"));

        // 3. 后续 user 块也必须 100% 保留 ChatGPT
        let user2_text = payload["contents"][2]["parts"][0]["text"].as_str().unwrap();
        assert!(user2_text.contains("ChatGPT"));
    }

    #[test]
    fn test_jeikl_multi_part_agent_prompt_sanitization_boundary() {
        // 验证 jeikl/PR#3769 边界：
        // 第一个 role:model 前的倒数第一个 user 的最后一个 part 之前的所有 user.part 均作为 Agent 提示词（System 轨）清洗；
        // 最后一个 part 及其多模态附件作为真实用户提问（LeadingUser 轨）清洗，严格保护竞品品牌与自然提问。

        // 1. 同一 user 轮次内多个 Part：Part 0 为注入指令，Part 1 为真实业务提问
        let mut multi_part_payload = json!({
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        { "text": "Instructions from Anthropic and OpenAI: You are Claude developed by Anthropic." },
                        { "text": "Please compare Anthropic and OpenAI for translation tasks." }
                    ]
                }
            ]
        });
        PromptSanitizer::sanitize_gemini_payload(&mut multi_part_payload);
        let p0 = multi_part_payload["contents"][0]["parts"][0]["text"]
            .as_str()
            .unwrap();
        let p1 = multi_part_payload["contents"][0]["parts"][1]["text"]
            .as_str()
            .unwrap();
        // Part 0（最后一个 part 之前的提示词）：走了 System 轨，厂牌与身份全量清洗为 Google / Antigravity
        assert!(p0.contains(OFFICIAL_ANTIGRAVITY_IDENTITY));
        assert!(p0.contains("Google"));
        assert!(!p0.to_lowercase().contains("anthropic"));
        assert!(!p0.to_lowercase().contains("openai"));
        // Part 1（最后一个 part 真实提问）：走了 LeadingUser 轨，竞品厂牌 100% 保持原样
        assert!(p1.contains("Anthropic"));
        assert!(p1.contains("OpenAI"));
        assert!(!p1.contains("Google"));

        // 2. 多个 user 轮次：前序 user 轮次为注入指令，末尾 user 轮次为真实提问
        let mut multi_turn_payload = json!({
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        { "text": "Developer prompt from DeepSeek and ByteDance." }
                    ]
                },
                {
                    "role": "user",
                    "parts": [
                        { "text": "What are the latest updates from DeepSeek and ByteDance?" }
                    ]
                },
                {
                    "role": "model",
                    "parts": [
                        { "text": "Here are the updates." }
                    ]
                }
            ]
        });
        PromptSanitizer::sanitize_gemini_payload(&mut multi_turn_payload);
        let turn0_text = multi_turn_payload["contents"][0]["parts"][0]["text"]
            .as_str()
            .unwrap();
        let turn1_text = multi_turn_payload["contents"][1]["parts"][0]["text"]
            .as_str()
            .unwrap();
        // 前序 user 轮次：走 System 轨清洗为 Google
        assert!(turn0_text.contains("Google"));
        assert!(!turn0_text.to_lowercase().contains("deepseek"));
        assert!(!turn0_text.contains("ByteDance"));
        // 倒数第一个 user 轮次（用户当轮提问）：竞品厂牌 100% 保持原样
        assert!(turn1_text.contains("DeepSeek"));
        assert!(turn1_text.contains("ByteDance"));
        assert!(!turn1_text.contains("Google"));

        // 3. 用户提问携带多模态附件（图片在文本后方）：精准定位最后一个文本 Part 作为真实提问
        let mut multimodal_payload = json!({
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        { "text": "System instructions provided by Anthropic." },
                        { "text": "Analyze Anthropic and OpenAI from this diagram:" },
                        { "inlineData": { "mimeType": "image/png", "data": "AAAA" } }
                    ]
                }
            ]
        });
        PromptSanitizer::sanitize_gemini_payload(&mut multimodal_payload);
        let mm_p0 = multimodal_payload["contents"][0]["parts"][0]["text"]
            .as_str()
            .unwrap();
        let mm_p1 = multimodal_payload["contents"][0]["parts"][1]["text"]
            .as_str()
            .unwrap();
        // 前置提示词：走 System 轨清洗
        assert!(mm_p0.contains("Google"));
        assert!(!mm_p0.to_lowercase().contains("anthropic"));
        // 真实提问：文本 Part 1 保持 Anthropic 和 OpenAI 原样
        assert!(mm_p1.contains("Anthropic"));
        assert!(mm_p1.contains("OpenAI"));
        // 附件 inlineData 完好保留
        assert_eq!(
            multimodal_payload["contents"][0]["parts"][2]["inlineData"]["mimeType"],
            "image/png"
        );
    }
}
