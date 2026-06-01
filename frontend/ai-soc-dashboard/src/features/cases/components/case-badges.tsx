import { Badge } from '@/components/ui/badge';
import { Icons } from '@/components/icons';
import type { CaseStatus, Severity } from '../api/types';

const severityClassName: Record<Severity, string> = {
  low: 'border-emerald-500/30 text-emerald-700 dark:text-emerald-300',
  medium: 'border-sky-500/30 text-sky-700 dark:text-sky-300',
  high: 'border-amber-500/30 text-amber-700 dark:text-amber-300',
  critical: 'border-red-500/30 text-red-700 dark:text-red-300'
};

const statusClassName: Record<CaseStatus, string> = {
  new: 'border-slate-500/30 text-slate-700 dark:text-slate-300',
  running: 'border-blue-500/30 text-blue-700 dark:text-blue-300',
  completed: 'border-emerald-500/30 text-emerald-700 dark:text-emerald-300',
  failed: 'border-red-500/30 text-red-700 dark:text-red-300',
  escalated: 'border-orange-500/30 text-orange-700 dark:text-orange-300'
};

type AgentRunStatus = 'ok' | 'error' | 'timeout' | 'cancelled' | 'running';

const agentStatusClassName: Record<AgentRunStatus, string> = {
  ok: 'border-emerald-500/30 text-emerald-700 dark:text-emerald-300',
  error: 'border-red-500/30 text-red-700 dark:text-red-300',
  timeout: 'border-amber-500/30 text-amber-700 dark:text-amber-300',
  cancelled: 'border-slate-500/30 text-slate-700 dark:text-slate-300',
  running: 'border-blue-500/30 text-blue-700 dark:text-blue-300'
};

export function SeverityBadge({ severity }: { severity?: Severity | null }) {
  if (!severity) {
    return <Badge variant='outline'>unclassified</Badge>;
  }

  return (
    <Badge variant='outline' className={severityClassName[severity]}>
      <Icons.warning />
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: CaseStatus }) {
  const Icon =
    status === 'completed'
      ? Icons.circleCheck
      : status === 'failed'
        ? Icons.xCircle
        : status === 'running'
          ? Icons.spinner
          : Icons.clock;

  return (
    <Badge variant='outline' className={statusClassName[status]}>
      <Icon className={status === 'running' ? 'animate-spin' : undefined} />
      {status}
    </Badge>
  );
}

export function AgentStatusBadge({ status }: { status: AgentRunStatus }) {
  const Icon =
    status === 'ok'
      ? Icons.circleCheck
      : status === 'error'
        ? Icons.xCircle
        : status === 'timeout'
          ? Icons.clock
          : status === 'running'
            ? Icons.spinner
            : Icons.clock;

  return (
    <Badge variant='outline' className={agentStatusClassName[status]}>
      <Icon className={status === 'running' ? 'animate-spin' : undefined} />
      {status}
    </Badge>
  );
}
