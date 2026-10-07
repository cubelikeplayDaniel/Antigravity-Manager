import { create } from 'zustand';
import { AppConfig } from '../types/config';
import * as configService from '../services/configService';
import i18n from '../i18n';

// 规范化语言编码 (兼容方言与区域代码别名)
export function normalizeLanguageCode(code: string): string {
    if (!code) return 'en';
    if (code === 'zh-CN') return 'zh';
    if (code === 'ms' || code === 'ms-MY') return 'my';
    if (code.startsWith('zh-TW') || code.startsWith('zh-HK')) return 'zh-TW';
    if (code.startsWith('pt-')) return 'pt';
    if (code.startsWith('es-')) return 'es';
    if (code.startsWith('vi-')) return 'vi';
    return code;
}

// 竞态隔离与尾随批处理锁：杜绝高频连续操作（如快速连续切换语言、主题或滑块）时后端 I/O 乱序回滚
let isPersisting = false;
let pendingSaveConfig: AppConfig | null = null;
let saveSequence = 0;

async function executeSaveQueue(config: AppConfig): Promise<void> {
    if (isPersisting) {
        // 当前已有写入在进行中，仅暂存最新的配置，等待当前写入完成后尾随执行
        pendingSaveConfig = config;
        return;
    }

    isPersisting = true;
    try {
        await configService.saveConfig(config);
        const { isTauri } = await import('../utils/env');
        if (isTauri()) {
            const { invoke } = await import('@tauri-apps/api/core');
            await invoke('set_window_theme', { theme: config.theme }).catch(() => {});
        }
    } finally {
        isPersisting = false;
        // 如果在当前写入期间有新的配置更新到达，立即取出最新的尾随配置继续写入
        if (pendingSaveConfig) {
            const next = pendingSaveConfig;
            pendingSaveConfig = null;
            await executeSaveQueue(next);
        }
    }
}

interface ConfigState {
    config: AppConfig | null;
    loading: boolean;
    error: string | null;

    // Actions
    loadConfig: () => Promise<void>;
    saveConfig: (config: AppConfig, silent?: boolean) => Promise<void>;
    updateTheme: (theme: string) => Promise<void>;
    updateLanguage: (language: string) => Promise<void>;
    toggleShowAllQuotas: () => void;
    showAllQuotas: boolean;
    toggleMenuItem: (path: string) => Promise<void>;
    isMenuItemHidden: (path: string) => boolean;
}

export const useConfigStore = create<ConfigState>((set, get) => ({
    config: null,
    loading: false,
    error: null,
    showAllQuotas: localStorage.getItem('antigravity_show_all_quotas') === 'true',

    loadConfig: async () => {
        set({ loading: true, error: null });
        try {
            const config = await configService.loadConfig();
            set({ config, loading: false });
        } catch (error) {
            set({ error: String(error), loading: false });
        }
    },

    saveConfig: async (config: AppConfig, silent: boolean = false) => {
        const currentSeq = ++saveSequence;
        // 1. 同步立即乐观更新 Zustand store 状态
        // 确保所有订阅组件与后续读操作即刻获取最新配置，彻底消灭渲染时差与闭包陈旧值
        set({ config, loading: !silent, error: null });

        try {
            // 2. 串行/尾随有序持久化，杜绝连续点击触发并发写竞态
            await executeSaveQueue(config);
            if (currentSeq === saveSequence) {
                set({ loading: false });
            }
        } catch (error) {
            if (currentSeq === saveSequence) {
                set({ error: String(error), loading: false });
            }
            throw error;
        }
    },

    updateTheme: async (theme: string) => {
        const current = get().config;
        if (!current || current.theme === theme) return;

        const latest = get().config || current;
        const newConfig = { ...latest, theme };
        await get().saveConfig(newConfig, true);
    },

    updateLanguage: async (language: string) => {
        const current = get().config;
        if (!current) return;

        const normalized = normalizeLanguageCode(language);
        if (current.language === normalized && i18n.language === normalized) return;

        // 1. 同步切换物理布局方向与 i18n
        document.documentElement.dir = normalized === 'ar' ? 'rtl' : 'ltr';
        await i18n.changeLanguage(normalized);

        // 2. 始终基于最新的 store 状态生成新配置并保存
        const latest = get().config || current;
        const newConfig = { ...latest, language: normalized };
        await get().saveConfig(newConfig, true);
    },

    toggleShowAllQuotas: () => {
        const current = get().showAllQuotas;
        const next = !current;
        localStorage.setItem('antigravity_show_all_quotas', String(next));
        set({ showAllQuotas: next });
    },

    toggleMenuItem: async (path: string) => {
        const { config } = get();
        if (!config) return;

        const hiddenItems = config.hidden_menu_items || [];
        const isHidden = hiddenItems.includes(path);

        const newHiddenItems = isHidden
            ? hiddenItems.filter(item => item !== path)
            : [...hiddenItems, path];

        const newConfig = { ...config, hidden_menu_items: newHiddenItems };
        await get().saveConfig(newConfig, true);
    },

    isMenuItemHidden: (path: string) => {
        const { config } = get();
        if (!config) return false;
        return (config.hidden_menu_items || []).includes(path);
    },
}));
