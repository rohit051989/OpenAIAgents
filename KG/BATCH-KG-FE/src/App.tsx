import React, { useMemo, useState } from 'react';
import { useChatStore } from '@/store/chatStore';
import { AppHeader } from '@/components/layout/AppHeader';
import { ChatWindow } from '@/components/chat/ChatWindow';
import { GraphPanel } from '@/components/visualization/GraphPanel';
import { DetailsPanel } from '@/components/details/DetailsPanel';
import type { GraphData, Message } from '@/types';
import styles from './App.module.css';

const App: React.FC = () => {
  const messages = useChatStore((s) => s.messages);

  // Track which assistant message is "selected" for the details panel
  const [selectedMessageId, setSelectedMessageId] = useState<string | null>(null);

  // The selected message — or fall back to the latest assistant message
  const activeMessage = useMemo<Message | null>(() => {
    if (selectedMessageId) {
      return messages.find((m) => m.id === selectedMessageId) ?? null;
    }
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === 'assistant') return messages[i];
    }
    return null;
  }, [messages, selectedMessageId]);

  // GraphData always comes from the active message
  const activeGraphData = useMemo<GraphData | null>(
    () => activeMessage?.graphData ?? null,
    [activeMessage],
  );

  return (
    <div className={styles.layout}>
      <AppHeader />

      <div className={styles.body}>
        {/* Column 1 — Chat */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <div className={styles.cardTitle}>AI Assistant</div>
            <div className={styles.cardSubtitle}>Ask questions about your Spring Batch jobs</div>
          </div>
          <div className={styles.cardBody}>
            <ChatWindow onSelectMessage={setSelectedMessageId} />
          </div>
        </div>

        {/* Column 2 — Graph */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <div className={styles.cardTitle}>Dependency Graph</div>
            <div className={styles.cardSubtitle}>Visualize job dependency chains</div>
          </div>
          <div className={styles.cardBody}>
            <GraphPanel graphData={activeGraphData} />
          </div>
        </div>

        {/* Column 3 — Details */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <div className={styles.cardTitle}>Execution Trace</div>
            <div className={styles.cardSubtitle}>Inspect agent steps and reasoning</div>
          </div>
          <div className={styles.cardBody}>
            <DetailsPanel message={activeMessage} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
