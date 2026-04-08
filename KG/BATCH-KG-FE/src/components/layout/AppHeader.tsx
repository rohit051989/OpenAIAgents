/**
 * AppHeader - top bar with app branding and LLM provider selector.
 */

import { useEffect } from 'react';
import type { LLMProvider } from '@/types';
import { useConfigStore } from '@/store/configStore';
import { useChatStore } from '@/store/chatStore';
import styles from './AppHeader.module.css';

const PROVIDER_LABELS: Record<LLMProvider, string> = {
  openai: 'OpenAI',
  azure_openai: 'Azure OpenAI',
  aws_bedrock: 'AWS Bedrock',
  google_gemini: 'Google Gemini',
};

export function AppHeader() {
  const loadProviders = useConfigStore((s) => s.loadProviders);
  const llmProvider = useConfigStore((s) => s.llmProvider);
  const availableProviders = useConfigStore((s) => s.availableProviders);
  const setLlmProvider = useConfigStore((s) => s.setLlmProvider);
  const clearMessages = useChatStore((s) => s.clearMessages);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  const providers: LLMProvider[] =
    availableProviders.length > 0
      ? availableProviders
      : (['openai', 'azure_openai', 'aws_bedrock', 'google_gemini'] as LLMProvider[]);

  return (
    <header className={styles.header}>
      <div className={styles.brand}>
        <span className={styles.title}>Spring Batch KG Agent</span>
        <span className={styles.subtitle}>AI-powered knowledge graph assistant for Spring Batch</span>
      </div>
      <div className={styles.controls}>
        <label className={styles.providerLabel} htmlFor="llm-select">Model</label>
        <select
          id="llm-select"
          className={styles.providerSelect}
          value={llmProvider}
          onChange={(e) => setLlmProvider(e.target.value as LLMProvider)}
        >
          {providers.map((p) => (
            <option key={p} value={p}>{PROVIDER_LABELS[p] ?? p}</option>
          ))}
        </select>
        <button className={styles.clearBtn} onClick={clearMessages}>Clear Chat</button>
      </div>
    </header>
  );
}