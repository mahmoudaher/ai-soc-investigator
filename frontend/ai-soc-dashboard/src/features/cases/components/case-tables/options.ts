import type { CaseStatus, Severity } from '../../api/types';

export const STATUS_OPTIONS: { value: CaseStatus; label: string }[] = [
  { value: 'new', label: 'New' },
  { value: 'running', label: 'Running' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'escalated', label: 'Escalated' }
];

export const SEVERITY_OPTIONS: { value: Severity; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' }
];
