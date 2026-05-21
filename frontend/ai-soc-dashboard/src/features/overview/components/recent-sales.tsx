'use client';

import Link from 'next/link';
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useQuery } from '@tanstack/react-query';
import { caseSummaryQueryOptions } from '@/features/cases/api/queries';
import { SeverityBadge, StatusBadge } from '@/features/cases/components/case-badges';

function titleFromRawAlert(rawAlert: Record<string, unknown>) {
  return typeof rawAlert.title === 'string' ? rawAlert.title : 'Wazuh alert investigation';
}

export function RecentSales() {
  const { data, isError, isLoading } = useQuery(caseSummaryQueryOptions());
  const cases = (data ?? []).slice(0, 5);

  return (
    <Card className='h-full'>
      <CardHeader>
        <CardTitle>Recent Cases</CardTitle>
        <CardDescription>Latest persisted investigations from the case database.</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading && (
          <div className='space-y-4'>
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className='h-12 rounded-md' />
            ))}
          </div>
        )}

        {isError && (
          <p className='text-muted-foreground text-sm'>
            Start the FastAPI backend to display recent cases.
          </p>
        )}

        {!isLoading && !isError && cases.length === 0 && (
          <p className='text-muted-foreground text-sm'>No cases have been ingested yet.</p>
        )}

        {!isLoading && !isError && cases.length > 0 && (
          <div className='space-y-4'>
            {cases.map((caseFile) => (
              <Link
                key={caseFile.case_id}
                href={`/dashboard/cases/${caseFile.case_id}`}
                aria-label={`Open case ${caseFile.case_id}`}
                className='block rounded-md border p-3 transition-colors hover:bg-muted/50'
              >
                <div className='flex items-start justify-between gap-3'>
                  <div className='min-w-0'>
                    <p className='truncate text-sm font-medium'>{titleFromRawAlert(caseFile.raw_alert)}</p>
                    <p className='text-muted-foreground mt-1 truncate text-xs'>
                      {caseFile.case_id}
                    </p>
                  </div>
                  <div className='flex shrink-0 flex-col items-end gap-1'>
                    <StatusBadge status={caseFile.status} />
                    <SeverityBadge severity={caseFile.severity} />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
