/**
 * MessageBubble — renders a single chat message (user or assistant).
 *
 * User messages show a Claude-style action toolbar in the bottom-right on hover:
 *   ✏ Edit   → opens inline edit mode (edit text then press Enter / Retry)
 *   ↺ Retry  → re-sends the exact same message without editing
 */

import { useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import type { Message } from '@/types';
import styles from './MessageBubble.module.css';

interface Props {
  message: Message;
  onSelect?: () => void;
  onEdit?: (newContent: string) => void;
  onRetry?: () => void;
}

export function MessageBubble({ message, onSelect, onEdit, onRetry }: Props) {
  const isUser = message.role === 'user';
  const [isEditing, setIsEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  function startEdit() {
    setDraft(message.content);
    setIsEditing(true);
    setTimeout(() => {
      textareaRef.current?.focus();
      textareaRef.current?.select();
    }, 0);
  }

  function cancelEdit() {
    setIsEditing(false);
    setDraft('');
  }

  function commitEdit() {
    const trimmed = draft.trim();
    if (trimmed) onEdit?.(trimmed);
    setIsEditing(false);
    setDraft('');
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); commitEdit(); }
    if (e.key === 'Escape') cancelEdit();
  }

  return (
    <div
      className={`${styles.wrapper} ${isUser ? styles.user : styles.assistant}`}
      onClick={!isEditing && !isUser ? onSelect : undefined}
      style={!isEditing && !isUser && onSelect ? { cursor: 'pointer' } : undefined}
    >
      <div className={styles.avatar}>{isUser ? '👤' : '🤖'}</div>

      <div className={styles.bubble}>
        {isEditing ? (
          /* ── Inline edit mode ── */
          <div className={styles.editArea}>
            <textarea
              ref={textareaRef}
              className={styles.editTextarea}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={Math.max(2, draft.split('\n').length)}
            />
            <div className={styles.editActions}>
              <button className={styles.cancelBtn} onClick={cancelEdit}>Cancel</button>
              <button className={styles.retryBtn} onClick={commitEdit} disabled={!draft.trim()}>
                Send ↩
              </button>
            </div>
          </div>
        ) : (
          /* ── Normal display mode ── */
          <div className={styles.content}>
            {isUser ? message.content : <ReactMarkdown>{message.content}</ReactMarkdown>}
          </div>
        )}

        {!isUser && message.graphData && !isEditing && (
          <p className={styles.graphHint}>↗ Graph visible in center panel</p>
        )}

        {!isEditing && (
          <time className={styles.timestamp}>
            {new Date(message.timestamp).toLocaleTimeString()}
          </time>
        )}

        {/* Claude-style bottom-right action toolbar — user messages only, on hover */}
        {isUser && (onEdit || onRetry) && !isEditing && (
          <div className={styles.actionBar}>
            {onEdit && (
              <button
                className={styles.actionBtn}
                onClick={startEdit}
                title="Edit message"
                aria-label="Edit message"
              >
                {/* pencil icon */}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                  <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                </svg>
              </button>
            )}
            {onRetry && (
              <button
                className={styles.actionBtn}
                onClick={onRetry}
                title="Retry (resend unchanged)"
                aria-label="Retry message"
              >
                {/* rotate-ccw icon */}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="1 4 1 10 7 10"/>
                  <path d="M3.51 15a9 9 0 1 0 .49-3.51"/>
                </svg>
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
