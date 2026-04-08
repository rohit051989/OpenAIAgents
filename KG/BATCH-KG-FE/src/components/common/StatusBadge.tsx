import React from 'react';
import type { ConnectionStatus as ConnectionStatusType } from '@/types';
import styles from './StatusBadge.module.css';

interface StatusBadgeProps {
  status: ConnectionStatusType;
}

const LABEL_MAP: Record<ConnectionStatusType, string> = {
  disconnected: 'Disconnected',
  connecting: 'Connecting…',
  connected: 'Connected',
  error: 'Error',
};

const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => (
  <span className={`${styles.badge} ${styles[status]}`}>
    <span className={styles.dot} />
    {LABEL_MAP[status]}
  </span>
);

export { StatusBadge };
export default StatusBadge;
