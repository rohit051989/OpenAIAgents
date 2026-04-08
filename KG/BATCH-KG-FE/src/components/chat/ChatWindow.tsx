/**
 * ChatWindow — scrollable message list + input bar.
 */

import { useEffect, useRef } from 'react';
import { useChat } from '@/hooks/useChat';
import { ChatInput } from './ChatInput';
import { MessageBubble } from './MessageBubble';
import styles from './ChatWindow.module.css';

interface Props {
  onSelectMessage?: (id: string) => void;
}

export function ChatWindow({ onSelectMessage }: Props) {
  const { messages, isLoading, error, submit, editAndRetry, dismissError } = useChat();
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  return (
    <div className={styles.root}>
      <div className={styles.messages}>
        {messages.length === 0 && (
          <div className={styles.empty}>
            <span className={styles.emptyIcon}>🤖</span>
            <p className={styles.emptyTitle}>Spring Batch Multi-Agent Assistant</p>
            <p className={styles.emptyHint}>
              Ask a question about your Spring Batch jobs, executions, or performance.
            </p>
          </div>
        )}

        {messages.map((msg) => (
          <MessageBubble
            key={msg.id}
            message={msg}
            onSelect={msg.role === 'assistant' ? () => onSelectMessage?.(msg.id) : undefined}
            onEdit={msg.role === 'user' && !isLoading ? (newContent) => editAndRetry(msg.id, newContent) : undefined}
            onRetry={msg.role === 'user' && !isLoading ? () => editAndRetry(msg.id, msg.content) : undefined}
          />
        ))}

        {isLoading && (
          <div className={styles.loadingRow}>
            <div className={styles.typingIndicator}>
              <span /><span /><span />
            </div>
            <span className={styles.loadingText}>Agents working…</span>
          </div>
        )}

        {error && (
          <div className={styles.errorBanner}>
            ⚠ {error}
            <button className={styles.dismissBtn} onClick={dismissError}>✕</button>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <ChatInput
        onSubmit={submit}
        disabled={isLoading}
        placeholder="Ask about Spring Batch data…"
      />
    </div>
  );
}
