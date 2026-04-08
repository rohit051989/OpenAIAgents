/**
 * ExecutionLog — expandable panel showing agent execution steps.
 */

import { useState } from 'react';
import type { ExecutionLogEntry, ExecutionPlan } from '@/types';
import styles from './ExecutionLog.module.css';

interface Props {
  executionLog: ExecutionLogEntry[];
  plan?: ExecutionPlan;
  stepResults?: Record<string, unknown>;
}

export function ExecutionLog({ executionLog, plan, stepResults }: Props) {
  const [showLog, setShowLog] = useState(false);
  const [showPlan, setShowPlan] = useState(false);
  const [showResults, setShowResults] = useState(false);

  return (
    <div className={styles.root}>
      {executionLog.length > 0 && (
        <div className={styles.section}>
          <button className={styles.toggle} onClick={() => setShowLog((v) => !v)}>
            {showLog ? '▾' : '▸'} Execution Flow ({executionLog.length} steps)
          </button>
          {showLog && (
            <ul className={styles.logList}>
              {executionLog.map((entry, i) => (
                <li key={i} className={styles.logEntry}>
                  <span className={styles.agent}>{entry.agent}</span>
                  <span className={styles.logMsg}>{entry.message}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {plan && (
        <div className={styles.section}>
          <button className={styles.toggle} onClick={() => setShowPlan((v) => !v)}>
            {showPlan ? '▾' : '▸'} Execution Plan
          </button>
          {showPlan && (
            <pre className={styles.json}>{JSON.stringify(plan, null, 2)}</pre>
          )}
        </div>
      )}

      {stepResults && Object.keys(stepResults).length > 0 && (
        <div className={styles.section}>
          <button className={styles.toggle} onClick={() => setShowResults((v) => !v)}>
            {showResults ? '▾' : '▸'} Raw Results
          </button>
          {showResults && (
            <pre className={styles.json}>{JSON.stringify(stepResults, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  );
}
