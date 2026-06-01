import type { CaseFile, Severity } from '@/features/cases/api/types';

type MonthBucket = {
  month: string;
  open: number;
  closed: number;
};

type SourceBucket = {
  source: string;
  cases: number;
};

type SeverityBucket = {
  severity: Severity | 'unknown';
  cases: number;
};

const CLOSED_STATUSES = new Set(['completed', 'failed']);
const DEFAULT_MONTH_WINDOW = 6;
const MONTH_FORMATTER = new Intl.DateTimeFormat('en', { month: 'short' });

function monthKey(date: Date) {
  const month = String(date.getMonth() + 1).padStart(2, '0');
  return `${date.getFullYear()}-${month}`;
}

function monthLabel(date: Date) {
  return MONTH_FORMATTER.format(date);
}

export function buildThroughputSeries(
  cases: CaseFile[],
  months = DEFAULT_MONTH_WINDOW,
  now = new Date()
): MonthBucket[] {
  const buckets = new Map<string, MonthBucket>();

  for (let offset = months - 1; offset >= 0; offset -= 1) {
    const date = new Date(now.getFullYear(), now.getMonth() - offset, 1);
    buckets.set(monthKey(date), {
      month: monthLabel(date),
      open: 0,
      closed: 0
    });
  }

  for (const item of cases) {
    const createdAt = new Date(item.created_at);
    const key = monthKey(new Date(createdAt.getFullYear(), createdAt.getMonth(), 1));
    const bucket = buckets.get(key);

    if (!bucket) continue;

    if (CLOSED_STATUSES.has(item.status)) {
      bucket.closed += 1;
    } else {
      bucket.open += 1;
    }
  }

  return Array.from(buckets.values());
}

export function buildSourceSeries(cases: CaseFile[]): SourceBucket[] {
  const counts = new Map<string, number>();

  for (const item of cases) {
    const source = item.source?.trim() || 'unknown';
    counts.set(source, (counts.get(source) ?? 0) + 1);
  }

  return Array.from(counts.entries())
    .map(([source, cases]) => ({ source, cases }))
    .sort((a, b) => b.cases - a.cases);
}

export function buildSeverityMix(cases: CaseFile[]): SeverityBucket[] {
  const buckets: Record<Severity | 'unknown', number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0
  };

  for (const item of cases) {
    const severity = item.severity ?? 'unknown';
    buckets[severity] = (buckets[severity] ?? 0) + 1;
  }

  return (['critical', 'high', 'medium', 'low', 'unknown'] as const).map((severity) => ({
    severity,
    cases: buckets[severity]
  }));
}
