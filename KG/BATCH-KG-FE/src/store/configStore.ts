/**
 * configStore.ts
 *
 * Zustand store for LLM provider selection.
 * MCP connection management is handled entirely by the backend.
 */

import { create } from 'zustand';
import type { LLMProvider } from '@/types';
import { fetchAvailableProviders } from '@/services/agentService';

interface ConfigState {
  llmProvider: LLMProvider;
  availableProviders: LLMProvider[];

  setLlmProvider: (provider: LLMProvider) => void;
  loadProviders: () => Promise<void>;
}

export const useConfigStore = create<ConfigState>((set, get) => ({
  llmProvider: 'openai',
  availableProviders: [],

  setLlmProvider: (provider) => set({ llmProvider: provider }),

  loadProviders: async () => {
    try {
      const providers = await fetchAvailableProviders();
      set({ availableProviders: providers });
      if (providers.length > 0 && !providers.includes(get().llmProvider)) {
        set({ llmProvider: providers[0] });
      }
    } catch {
      // Non-fatal — provider list just stays empty
    }
  },
}));
