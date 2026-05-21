'use client';

import {
  Card,
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Icons } from '@/components/icons';
import { useQuery } from '@tanstack/react-query';
import { caseSummaryQueryOptions } from '@/features/cases/api/queries';
import type { CaseFile } from '@/features/cases/api/types';

function countCases(cases: CaseFile[]) {
  return {
    total: cases.length,
    active: cases.filter((item) => ['new', 'running', 'escalated'].includes(item.status)).length,
    urgent: cases.filter((item) => ['critical', 'high'].includes(item.severity ?? '')).length,
    completed: cases.filter((item) => item.status === 'completed').length,
    evidence: cases.reduce((total, item) => total + item.evidence.length, 0)
  };
}

function StatCard({
  label,
  value,
  badge,
  note,
  detail,
  icon
}: {
  label: string;
  value: string | number;
  badge: string;
  note: string;
  detail: string;
  icon: React.ReactNode;
}) {
  return (
    <Card className='@container/card'>
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className='text-2xl font-semibold tabular-nums @[250px]/card:text-3xl'>
          {value}
        </CardTitle>
        <CardAction>
          <Badge variant='outline'>
            {icon}
            {badge}
          </Badge>
        </CardAction>
      </CardHeader>
      <CardFooter className='flex-col items-start gap-1.5 text-sm'>
        <div className='line-clamp-1 flex gap-2 font-medium'>{note}</div>
        <div className='text-muted-foreground'>{detail}</div>
      </CardFooter>
    </Card>
  );
}

export function CaseStats() {
  const { data, isError, isLoading } = useQuery(caseSummaryQueryOptions());
  const stats = countCases(data ?? []);

  if (isLoading) {
    return (
      <div className='grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4'>
        {Array.from({ length: 4 }).map((_, index) => (
          <Card key={index} className='h-36 animate-pulse' />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className='grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4'>
        <StatCard
          label='Backend status'
          value='Offline'
          badge='503'
          note='FastAPI is not responding'
          detail='Start the backend to load live case metrics.'
          icon={<Icons.alertCircle />}
        />
      </div>
    );
  }

  return (
    <div className='*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-1 gap-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs md:grid-cols-2 lg:grid-cols-4'>
      <StatCard
        label='Total cases'
        value={stats.total}
        badge='Live'
        note='Cases loaded from FastAPI'
        detail='Includes current and past investigations.'
        icon={<Icons.checks />}
      />
      <StatCard
        label='Active investigations'
        value={stats.active}
        badge='Open'
        note='Needs analyst attention'
        detail='New, running, and escalated case files.'
        icon={<Icons.clock />}
      />
      <StatCard
        label='High risk cases'
        value={stats.urgent}
        badge='Priority'
        note='Critical or high severity'
        detail='Use this count to drive the presentation queue.'
        icon={<Icons.warning />}
      />
      <StatCard
        label='Evidence items'
        value={stats.evidence}
        badge={`${stats.completed} closed`}
        note='Collected by investigation agents'
        detail='Evidence, timeline, MITRE, and response context.'
        icon={<Icons.page />}
      />
    </div>
  );
}
