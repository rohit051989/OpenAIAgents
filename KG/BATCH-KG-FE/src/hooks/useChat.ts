import { useCallback } from 'react';
import { useChatStore } from '@/store/chatStore';

export function useChat() {
  const messages = useChatStore((s) => s.messages);
  const isLoading = useChatStore((s) => s.isLoading);
  const error = useChatStore((s) => s.error);
  const sendMessage = useChatStore((s) => s.sendMessage);
  const editAndRetryStore = useChatStore((s) => s.editAndRetry);
  const clearMessages = useChatStore((s) => s.clearMessages);
  const dismissError = useChatStore((s) => s.dismissError);

  const submit = useCallback(
    (content: string) => {
      if (content.trim() && !isLoading) {
        sendMessage(content.trim());
      }
    },
    [isLoading, sendMessage],
  );

  const editAndRetry = useCallback(
    (messageId: string, newContent: string) => {
      if (!isLoading) editAndRetryStore(messageId, newContent);
    },
    [isLoading, editAndRetryStore],
  );

  return { messages, isLoading, error, submit, editAndRetry, clearMessages, dismissError };
}
