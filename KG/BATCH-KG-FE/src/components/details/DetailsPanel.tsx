/**
 * DetailsPanel — column 3: shows agent execution steps and plan for the
 * currently selected (or latest) assistant message.
 */

import { useState } from 'react';
import type { Message, ExecutionLogEntry, PlanStep } from '@/types';
import styles from './DetailsPanel.module.css';

interface Props {
  message: Message | null;
}

function AgentBadge({ agent }: { agent: string }) {
  const lower = agent.toLowerCase();
  let variant = styles.badgeDefault;
  if (lower.includes('planner')) variant = styles.badgePlanner;
  else if (lower.includes('summar')) variant = styles.badgeSummarizer;
  else if (lower.includes('step')) variant = styles.badgeStep;
  return <span className={`${styles.badge} ${variant}`}>{agent}</span>;
}

function StepTypeTag({ type }: { type: string }) {
  const variant = type === 'direct_tool' ? styles.tagTool : styles.tagCypher;
  return <span className={`${styles.tag} ${variant}`}>{type}</span>;
}

function LogEntry({ entry }: { entry: ExecutionLogEntry }) {
  return (
    <div className={styles.logEntry}>
      <AgentBadge agent={entry.agent} />
      <p className={styles.logMsg}>{entry.message}</p>
    </div>
  );
}

function PlanStepCard({ step }: { step: PlanStep }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={styles.planCard}>
      <div className={styles.planCardHeader} onClick={() => setExpanded((v) => !v)}>
        <div className={styles.planCardLeft}>
          <span className={styles.stepNum}>{step.step}</span>
          <span className={styles.stepAction}>{step.action}</span>
        </div>
        <div className={styles.planCardRight}>
          <StepTypeTag type={step.type} />
          <span className={styles.chevron}>{expanded ? '▾' : '▸'}</span>
        </div>
      </div>
      {expanded && (
        <div className={styles.planCardBody}>
          {step.tool && (
            <div className={styles.detailRow}>
              <span className={styles.detailKey}>Tool</span>
              <code className={styles.detailVal}>{step.tool}</code>
            </div>
          )}
          {step.depends_on && step.depends_on.length > 0 && (
            <div className={styles.detailRow}>
              <span className={styles.detailKey}>Depends on</span>
              <span className={styles.detailVal}>steps {step.depends_on.join(', ')}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function DetailsPanel({ message }: Props) {
  const [activeTab, setActiveTab] = useState<'log' | 'plan'>('log');

  if (!message) {
    return (
      <div className={styles.empty}>
        <span className={styles.emptyIcon}>🔍</span>
        <p className={styles.emptyTitle}>No details yet</p>
        <p className={styles.emptyHint}>
          Send a message and agent execution details will appear here.
        </p>
      </div>
    );
  }

  const hasLog = (message.executionLog?.length ?? 0) > 0;
  const hasPlan = !!message.plan;

  return (
    <div className={styles.root}>
      {/* Tabs */}
      {(hasLog || hasPlan) && (
        <div className={styles.tabs}>
          <button
            className={`${styles.tab} ${activeTab === 'log' ? styles.tabActive : ''}`}
            onClick={() => setActiveTab('log')}
          >
            Execution Log
            {hasLog && (
              <span className={styles.tabCount}>{message.executionLog!.length}</span>
            )}
          </button>
          {hasPlan && (
            <button
              className={`${styles.tab} ${activeTab === 'plan' ? styles.tabActive : ''}`}
              onClick={() => setActiveTab('plan')}
            >
              Plan
              <span className={styles.tabCount}>{message.plan!.plan.length} steps</span>
            </button>
          )}
        </div>
      )}

      <div className={styles.content}>
        {/* Execution Log tab */}
        {activeTab === 'log' && hasLog && (
          <div className={styles.logList}>
            {message.executionLog!.map((entry, i) => (
              <LogEntry key={i} entry={entry} />
            ))}
          </div>
        )}

        {/* Plan tab */}
        {activeTab === 'plan' && hasPlan && (
          <div className={styles.planList}>
            {message.plan!.strategy && (
              <div className={styles.planMeta}>
                <span className={styles.metaKey}>Strategy</span>
                <span className={`${styles.metaTag} ${styles.tagStrategy}`}>
                  {message.plan!.strategy}
                </span>
                {message.plan!.complexity && (
                  <>
                    <span className={styles.metaKey}>Complexity</span>
                    <span className={`${styles.metaTag} ${styles.tagComplexity}`}>
                      {message.plan!.complexity}
                    </span>
                  </>
                )}
              </div>
            )}
            {message.plan!.plan.map((step) => (
              <PlanStepCard key={step.step} step={step} />
            ))}
          </div>
        )}

        {/* No data state for log tab */}
        {activeTab === 'log' && !hasLog && (
          <p className={styles.noData}>No execution log available.</p>
        )}
      </div>
    </div>
  );
}
