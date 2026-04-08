/**
 * ChatInput — message input bar at the bottom of the chat window.
 */

import { useState, type KeyboardEvent, type FormEvent } from 'react';
import styles from './ChatInput.module.css';

interface Props {
  onSubmit: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
}

export function ChatInput({ onSubmit, disabled = false, placeholder }: Props) {
  const [value, setValue] = useState('');

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (value.trim() && !disabled) {
      onSubmit(value.trim());
      setValue('');
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit(e as unknown as FormEvent);
    }
  };

  return (
    <form className={styles.form} onSubmit={submit}>
      <textarea
        className={styles.textarea}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        placeholder={placeholder ?? 'Ask about Spring Batch data… (Enter to send, Shift+Enter for newline)'}
        rows={1}
      />
      <button
        type="submit"
        className={styles.sendBtn}
        disabled={disabled || !value.trim()}
        aria-label="Send message"
      >
        ➤
      </button>
    </form>
  );
}
