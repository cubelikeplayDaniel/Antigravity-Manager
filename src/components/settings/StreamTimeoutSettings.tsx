import React, { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Timer, RotateCcw, Save, Check, Sparkles, Clock, RefreshCw } from "lucide-react";
import { StreamTimeoutConfig } from "../../types/config";
import { showToast } from "../common/ToastContainer";

interface StreamTimeoutSettingsProps {
    config?: StreamTimeoutConfig;
    onChange: (config: StreamTimeoutConfig) => void;
    onSave?: () => Promise<void> | void;
}

const DEFAULT_TIMEOUTS: Required<StreamTimeoutConfig> = {
    initial_ttft_secs: 180,
    transition_secs: 180,
    streaming_sliding_secs: 45,
};

export const StreamTimeoutSettings: React.FC<StreamTimeoutSettingsProps> = ({
    config,
    onChange,
    onSave,
}) => {
    const { t } = useTranslation();
    const [isSaving, setIsSaving] = useState(false);
    const [savedSuccessfully, setSavedSuccessfully] = useState(false);

    // 编辑框预填预设默认值 (180, 180, 45)
    const [rawInputs, setRawInputs] = useState<{
        initial_ttft_secs: string;
        transition_secs: string;
        streaming_sliding_secs: string;
    }>({
        initial_ttft_secs: String(config?.initial_ttft_secs ?? DEFAULT_TIMEOUTS.initial_ttft_secs),
        transition_secs: String(config?.transition_secs ?? DEFAULT_TIMEOUTS.transition_secs),
        streaming_sliding_secs: String(config?.streaming_sliding_secs ?? DEFAULT_TIMEOUTS.streaming_sliding_secs),
    });

    // 确保若外部传入的 config 未定义字段，自动以预设默认值通知父级
    useEffect(() => {
        if (
            !config ||
            config.initial_ttft_secs === undefined ||
            config.transition_secs === undefined ||
            config.streaming_sliding_secs === undefined
        ) {
            onChange({
                initial_ttft_secs: config?.initial_ttft_secs ?? DEFAULT_TIMEOUTS.initial_ttft_secs,
                transition_secs: config?.transition_secs ?? DEFAULT_TIMEOUTS.transition_secs,
                streaming_sliding_secs: config?.streaming_sliding_secs ?? DEFAULT_TIMEOUTS.streaming_sliding_secs,
            });
        }
    }, []);

    // 外部 config 变化时同步输入框展示
    useEffect(() => {
        setRawInputs({
            initial_ttft_secs: String(config?.initial_ttft_secs ?? DEFAULT_TIMEOUTS.initial_ttft_secs),
            transition_secs: String(config?.transition_secs ?? DEFAULT_TIMEOUTS.transition_secs),
            streaming_sliding_secs: String(config?.streaming_sliding_secs ?? DEFAULT_TIMEOUTS.streaming_sliding_secs),
        });
    }, [config?.initial_ttft_secs, config?.transition_secs, config?.streaming_sliding_secs]);

    const getCurrentNum = (field: keyof StreamTimeoutConfig): number => {
        const val = parseInt(rawInputs[field], 10);
        return isNaN(val) ? DEFAULT_TIMEOUTS[field] : val;
    };

    const handleInputChange = (field: keyof StreamTimeoutConfig, text: string) => {
        const filtered = text.replace(/[^0-9]/g, "");
        setRawInputs((prev) => ({ ...prev, [field]: filtered }));

        if (filtered !== "") {
            const num = parseInt(filtered, 10);
            if (!isNaN(num) && num > 0) {
                onChange({
                    initial_ttft_secs: field === "initial_ttft_secs" ? num : getCurrentNum("initial_ttft_secs"),
                    transition_secs: field === "transition_secs" ? num : getCurrentNum("transition_secs"),
                    streaming_sliding_secs: field === "streaming_sliding_secs" ? num : getCurrentNum("streaming_sliding_secs"),
                });
            }
        }
    };

    const handleInputBlur = (field: keyof StreamTimeoutConfig) => {
        if (rawInputs[field] === "" || parseInt(rawInputs[field], 10) <= 0) {
            const defVal = DEFAULT_TIMEOUTS[field];
            setRawInputs((prev) => ({ ...prev, [field]: String(defVal) }));
            onChange({
                initial_ttft_secs: field === "initial_ttft_secs" ? defVal : getCurrentNum("initial_ttft_secs"),
                transition_secs: field === "transition_secs" ? defVal : getCurrentNum("transition_secs"),
                streaming_sliding_secs: field === "streaming_sliding_secs" ? defVal : getCurrentNum("streaming_sliding_secs"),
            });
        }
    };

    const applyPreset = (field: keyof StreamTimeoutConfig, val: number) => {
        setRawInputs((prev) => ({ ...prev, [field]: String(val) }));
        onChange({
            initial_ttft_secs: field === "initial_ttft_secs" ? val : getCurrentNum("initial_ttft_secs"),
            transition_secs: field === "transition_secs" ? val : getCurrentNum("transition_secs"),
            streaming_sliding_secs: field === "streaming_sliding_secs" ? val : getCurrentNum("streaming_sliding_secs"),
        });
    };

    const handleResetDefaults = () => {
        setRawInputs({
            initial_ttft_secs: String(DEFAULT_TIMEOUTS.initial_ttft_secs),
            transition_secs: String(DEFAULT_TIMEOUTS.transition_secs),
            streaming_sliding_secs: String(DEFAULT_TIMEOUTS.streaming_sliding_secs),
        });
        onChange({ ...DEFAULT_TIMEOUTS });
        showToast(t("proxy.stream_timeouts.toast_reset", { defaultValue: "已恢复超时配置默认值" }), "info");
    };

    const handleSave = async () => {
        setIsSaving(true);
        try {
            if (onSave) {
                await onSave();
            }
            setSavedSuccessfully(true);
            showToast(t("common.success", { defaultValue: "设置已保存" }), "success");
            setTimeout(() => setSavedSuccessfully(false), 2000);
        } catch (error: any) {
            console.error("保存超时设置失败:", error);
            showToast(t("common.error", { defaultValue: "保存失败" }), "error");
        } finally {
            setIsSaving(false);
        }
    };

    const renderPresetButtons = (field: keyof StreamTimeoutConfig, presets: number[], defaultVal: number) => {
        const currentVal = getCurrentNum(field);
        return (
            <div className="flex flex-wrap items-center gap-1.5 pt-1">
                {presets.map((val) => {
                    const isSelected = currentVal === val;
                    const isDefault = val === defaultVal;
                    return (
                        <button
                            key={val}
                            type="button"
                            onClick={() => applyPreset(field, val)}
                            className={`px-2 py-0.5 text-[10px] rounded font-mono transition-colors cursor-pointer ${
                                isSelected
                                    ? "bg-blue-600 text-white font-bold shadow-xs"
                                    : "bg-white dark:bg-base-100 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-base-300 border border-gray-200 dark:border-base-300"
                            }`}
                        >
                            {val}s{isDefault ? ` (${t("common.default", { defaultValue: "默认" })})` : ""}
                        </button>
                    );
                })}
            </div>
        );
    };

    return (
        <div className="space-y-4 text-gray-800 dark:text-gray-200">
            {/* 顶栏说明提示 */}
            <div className="p-3 bg-amber-50/70 dark:bg-amber-950/20 rounded-xl border border-amber-200/70 dark:border-amber-800/40 text-xs leading-relaxed space-y-1">
                <div className="font-semibold text-amber-900 dark:text-amber-300 flex items-center gap-1.5">
                    <Sparkles size={14} className="text-amber-600 dark:text-amber-400" />
                    {t("proxy.stream_timeouts.banner_title", { defaultValue: "三阶段流式梯度超时与保活机制" })}
                </div>
                <p className="text-gray-600 dark:text-gray-400">
                    {t("proxy.stream_timeouts.banner_desc", {
                        defaultValue: "针对深度思考模型、超大上下文 Prefill、长历史压缩摘要及大文件代码写入场景，通过三阶段独立计时与全程底层心跳保活（: ping），彻底杜绝中间网关掐断、过渡断崖误杀与客户端重试死循环。"
                    })}
                </p>
            </div>

            {/* 核心三梯度超时配置网格 */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
                {/* 1. 首字排队宽限 */}
                <div className="p-3.5 bg-gray-50/70 dark:bg-base-200/60 rounded-xl border border-gray-200/70 dark:border-base-300 flex flex-col justify-between space-y-3">
                    <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
                                <Clock size={14} className="text-blue-500" />
                                {t("proxy.stream_timeouts.ttft_title", { defaultValue: "首字响应宽限 (TTFT)" })}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-blue-100/70 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300">
                                {t("proxy.stream_timeouts.default_badge", { defaultValue: "默认: 180s" })}
                            </span>
                        </div>
                        <p className="text-[11px] text-gray-500 dark:text-gray-400 leading-normal">
                            {t("proxy.stream_timeouts.ttft_desc", {
                                defaultValue: "涵盖上游冷启动排队、超大提示词 Prefill 与长历史压缩摘要任务的最大容忍时间。期间每 3 秒下发心跳保活。"
                            })}
                        </p>
                    </div>

                    <div className="space-y-2">
                        <div className="flex items-center gap-2 pt-1">
                            <input
                                type="text"
                                inputMode="numeric"
                                placeholder={String(DEFAULT_TIMEOUTS.initial_ttft_secs)}
                                value={rawInputs.initial_ttft_secs}
                                onChange={(e) => handleInputChange("initial_ttft_secs", e.target.value)}
                                onBlur={() => handleInputBlur("initial_ttft_secs")}
                                className="w-full px-3 py-1.5 border border-gray-300 dark:border-base-300 rounded-lg bg-white dark:bg-base-100 text-xs font-mono font-semibold text-gray-900 dark:text-base-content focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                            />
                            <span className="text-xs text-gray-500 font-medium shrink-0">
                                {t("common.seconds", { defaultValue: "秒" })}
                            </span>
                        </div>
                        {renderPresetButtons("initial_ttft_secs", [60, 180, 300, 600], DEFAULT_TIMEOUTS.initial_ttft_secs)}
                    </div>
                </div>

                {/* 2. 状态切换宽限 */}
                <div className="p-3.5 bg-gray-50/70 dark:bg-base-200/60 rounded-xl border border-gray-200/70 dark:border-base-300 flex flex-col justify-between space-y-3">
                    <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
                                <RefreshCw size={14} className="text-purple-500" />
                                {t("proxy.stream_timeouts.transition_title", { defaultValue: "状态切换宽限 (全新轮回)" })}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-purple-100/70 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300">
                                {t("proxy.stream_timeouts.default_badge", { defaultValue: "默认: 180s" })}
                            </span>
                        </div>
                        <p className="text-[11px] text-gray-500 dark:text-gray-400 leading-normal">
                            {t("proxy.stream_timeouts.transition_desc", {
                                defaultValue: "思考完毕至首个正文或工具调用出字的过渡期。思考结束时自适应重置计时器，为大文件写入等装配留出充分时间。"
                            })}
                        </p>
                    </div>

                    <div className="space-y-2">
                        <div className="flex items-center gap-2 pt-1">
                            <input
                                type="text"
                                inputMode="numeric"
                                placeholder={String(DEFAULT_TIMEOUTS.transition_secs)}
                                value={rawInputs.transition_secs}
                                onChange={(e) => handleInputChange("transition_secs", e.target.value)}
                                onBlur={() => handleInputBlur("transition_secs")}
                                className="w-full px-3 py-1.5 border border-gray-300 dark:border-base-300 rounded-lg bg-white dark:bg-base-100 text-xs font-mono font-semibold text-gray-900 dark:text-base-content focus:ring-2 focus:ring-purple-500/20 focus:border-purple-500"
                            />
                            <span className="text-xs text-gray-500 font-medium shrink-0">
                                {t("common.seconds", { defaultValue: "秒" })}
                            </span>
                        </div>
                        {renderPresetButtons("transition_secs", [60, 180, 300, 600], DEFAULT_TIMEOUTS.transition_secs)}
                    </div>
                </div>

                {/* 3. 稳态推流滑动超时 */}
                <div className="p-3.5 bg-gray-50/70 dark:bg-base-200/60 rounded-xl border border-gray-200/70 dark:border-base-300 flex flex-col justify-between space-y-3">
                    <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-gray-900 dark:text-white flex items-center gap-1.5">
                                <Timer size={14} className="text-emerald-500" />
                                {t("proxy.stream_timeouts.sliding_title", { defaultValue: "推流滑动超时 (Streaming)" })}
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-emerald-100/70 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300">
                                {t("proxy.stream_timeouts.default_badge_sliding", { defaultValue: "默认: 45s" })}
                            </span>
                        </div>
                        <p className="text-[11px] text-gray-500 dark:text-gray-400 leading-normal">
                            {t("proxy.stream_timeouts.sliding_desc", {
                                defaultValue: "持续吐字过程中相邻 Token 的最大允许静默间隔。若中途意外断流超过此时长，自动优雅截断收尾并保全已生成的代码。"
                            })}
                        </p>
                    </div>

                    <div className="space-y-2">
                        <div className="flex items-center gap-2 pt-1">
                            <input
                                type="text"
                                inputMode="numeric"
                                placeholder={String(DEFAULT_TIMEOUTS.streaming_sliding_secs)}
                                value={rawInputs.streaming_sliding_secs}
                                onChange={(e) => handleInputChange("streaming_sliding_secs", e.target.value)}
                                onBlur={() => handleInputBlur("streaming_sliding_secs")}
                                className="w-full px-3 py-1.5 border border-gray-300 dark:border-base-300 rounded-lg bg-white dark:bg-base-100 text-xs font-mono font-semibold text-gray-900 dark:text-base-content focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500"
                            />
                            <span className="text-xs text-gray-500 font-medium shrink-0">
                                {t("common.seconds", { defaultValue: "秒" })}
                            </span>
                        </div>
                        {renderPresetButtons("streaming_sliding_secs", [30, 45, 60, 120], DEFAULT_TIMEOUTS.streaming_sliding_secs)}
                    </div>
                </div>
            </div>

            {/* 底部操作工具栏 */}
            <div className="flex items-center justify-between pt-2 border-t border-gray-200/60 dark:border-base-300/60">
                <button
                    type="button"
                    onClick={handleResetDefaults}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:white bg-gray-100 dark:bg-base-200 hover:bg-gray-200 dark:hover:bg-base-300 rounded-lg transition-colors cursor-pointer"
                >
                    <RotateCcw size={13} />
                    {t("proxy.stream_timeouts.btn_reset", { defaultValue: "恢复默认值" })}
                </button>

                {onSave && (
                    <button
                        type="button"
                        onClick={handleSave}
                        disabled={isSaving}
                        className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white rounded-lg transition-all cursor-pointer ${
                            savedSuccessfully
                                ? "bg-emerald-600 hover:bg-emerald-700"
                                : "bg-blue-600 hover:bg-blue-700 shadow-xs"
                        } disabled:opacity-50`}
                    >
                        {savedSuccessfully ? (
                            <>
                                <Check size={13} />
                                {t("common.saved", { defaultValue: "已保存" })}
                            </>
                        ) : (
                            <>
                                <Save size={13} />
                                {isSaving
                                    ? t("common.saving", { defaultValue: "保存中..." })
                                    : t("proxy.stream_timeouts.btn_save", { defaultValue: "保存超时设置" })}
                            </>
                        )}
                    </button>
                )}
            </div>
        </div>
    );
};

export default StreamTimeoutSettings;
