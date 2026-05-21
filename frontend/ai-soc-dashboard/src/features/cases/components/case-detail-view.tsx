'use client';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Icons } from '@/components/icons';
import { useQuery } from '@tanstack/react-query';
import { caseByIdOptions, caseCheckpointsOptions } from '../api/queries';
import type { CaseFile } from '../api/types';
import { SeverityBadge, StatusBadge } from './case-badges';

type CaseDetailViewProps = {
  caseId: string;
};

function formatDate(value?: string | null) {
  if (!value) return 'Not available';

  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(new Date(value));
}

function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className='bg-muted/60 max-h-[360px] overflow-auto rounded-md p-3 text-xs leading-relaxed'>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function LoadingState() {
  return (
    <div className='space-y-4'>
      <div className='grid grid-cols-1 gap-4 md:grid-cols-4'>
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className='h-28 rounded-lg' />
        ))}
      </div>
      <Skeleton className='h-64 rounded-lg' />
      <Skeleton className='h-64 rounded-lg' />
    </div>
  );
}

function MetricCard({
  title,
  value,
  description
}: {
  title: string;
  value: React.ReactNode;
  description: string;
}) {
  return (
    <Card>
      <CardHeader className='pb-2'>
        <CardDescription>{title}</CardDescription>
        <CardTitle className='text-2xl'>{value}</CardTitle>
      </CardHeader>
      <CardContent className='text-muted-foreground text-sm'>{description}</CardContent>
    </Card>
  );
}

function RawAlertTitle({ caseFile }: { caseFile: CaseFile }) {
  const title = caseFile.raw_alert.title;
  return typeof title === 'string' && title.length > 0 ? title : 'Wazuh alert investigation';
}

export default function CaseDetailView({ caseId }: CaseDetailViewProps) {
  const caseQuery = useQuery(caseByIdOptions(caseId));
  const checkpointsQuery = useQuery(caseCheckpointsOptions(caseId));

  if (caseQuery.isLoading) {
    return <LoadingState />;
  }

  if (caseQuery.isError || !caseQuery.data?.case_file) {
    return (
      <Alert variant='destructive'>
        <Icons.alertCircle className='h-4 w-4' />
        <AlertTitle>Unable to open case</AlertTitle>
        <AlertDescription>
          {caseQuery.error instanceof Error
            ? caseQuery.error.message
            : 'Check that the FastAPI backend is running and the case exists.'}
        </AlertDescription>
      </Alert>
    );
  }

  const caseFile = caseQuery.data.case_file;
  const checkpoints = checkpointsQuery.data?.checkpoints ?? [];

  return (
    <div className='space-y-4'>
      <div className='grid grid-cols-1 gap-4 md:grid-cols-4'>
        <MetricCard
          title='Current status'
          value={<StatusBadge status={caseFile.status} />}
          description={`Last updated ${formatDate(caseFile.updated_at)}`}
        />
        <MetricCard
          title='Severity'
          value={<SeverityBadge severity={caseFile.severity} />}
          description={caseFile.category ?? 'Waiting for classification'}
        />
        <MetricCard
          title='Entities'
          value={caseFile.entities.length}
          description='Hosts, users, IPs, processes, files, and other extracted observables.'
        />
        <MetricCard
          title='Evidence'
          value={caseFile.evidence.length}
          description='Evidence items collected by the investigation workflow.'
        />
      </div>

      <Card>
        <CardHeader>
          <div className='flex flex-col gap-2 md:flex-row md:items-start md:justify-between'>
            <div>
              <CardTitle>
                <RawAlertTitle caseFile={caseFile} />
              </CardTitle>
              <CardDescription>
                Case {caseFile.case_id} from {caseFile.source ?? 'wazuh'} created{' '}
                {formatDate(caseFile.created_at)}
              </CardDescription>
            </div>
            <div className='flex flex-wrap gap-2'>
              {caseFile.tags.map((tag) => (
                <Badge key={tag} variant='secondary'>
                  {tag}
                </Badge>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className='space-y-4'>
          <p className='text-sm leading-6'>
            {caseFile.summary ??
              caseFile.triage?.summary ??
              'The case is ready for automated triage. Ingest a Wazuh alert with workflow enabled to populate the timeline, evidence, MITRE mapping, and recommendations.'}
          </p>

          {caseFile.triage && (
            <>
              <Separator />
              <div className='space-y-3'>
                <div className='flex items-center gap-2'>
                  <h3 className='font-semibold'>Triage assessment</h3>
                  <Badge variant='outline'>
                    {Math.round(caseFile.triage.confidence * 100)}% confidence
                  </Badge>
                </div>
                <p className='text-muted-foreground text-sm'>{caseFile.triage.summary}</p>
                <div className='grid gap-2 md:grid-cols-2'>
                  {caseFile.triage.plan.map((step, index) => (
                    <div key={`${step.goal}-${index}`} className='rounded-md border p-3'>
                      <div className='mb-1 flex items-center justify-between gap-2'>
                        <p className='text-sm font-medium'>{step.goal}</p>
                        <SeverityBadge severity={step.priority} />
                      </div>
                      <p className='text-muted-foreground text-sm'>{step.rationale}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <div className='grid grid-cols-1 gap-4 lg:grid-cols-2'>
        <Card>
          <CardHeader>
            <CardTitle>Investigation Timeline</CardTitle>
            <CardDescription>Agent-generated events in chronological order.</CardDescription>
          </CardHeader>
          <CardContent className='space-y-4'>
            {caseFile.timeline.length > 0 ? (
              caseFile.timeline.map((event) => (
                <div key={event.id} className='border-l-2 pl-4'>
                  <div className='flex flex-wrap items-center gap-2'>
                    <p className='font-medium'>{event.title}</p>
                    <Badge variant='outline'>{event.agent}</Badge>
                  </div>
                  <p className='text-muted-foreground text-xs'>{formatDate(event.timestamp)}</p>
                  <p className='mt-1 text-sm'>{event.description}</p>
                </div>
              ))
            ) : (
              <p className='text-muted-foreground text-sm'>No timeline events yet.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Entities</CardTitle>
            <CardDescription>Normalized observables extracted from the alert.</CardDescription>
          </CardHeader>
          <CardContent className='space-y-2'>
            {caseFile.entities.length > 0 ? (
              caseFile.entities.map((entity) => (
                <div key={entity.id} className='flex items-center justify-between rounded-md border p-3'>
                  <div>
                    <p className='font-medium'>{entity.value}</p>
                    <p className='text-muted-foreground text-xs'>{entity.type}</p>
                  </div>
                  <Badge variant='outline'>{Math.round(entity.confidence * 100)}%</Badge>
                </div>
              ))
            ) : (
              <p className='text-muted-foreground text-sm'>No entities extracted yet.</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className='grid grid-cols-1 gap-4 lg:grid-cols-2'>
        <Card>
          <CardHeader>
            <CardTitle>MITRE ATT&CK Mapping</CardTitle>
            <CardDescription>Techniques inferred from case evidence.</CardDescription>
          </CardHeader>
          <CardContent className='space-y-3'>
            {caseFile.mitre.length > 0 ? (
              caseFile.mitre.map((technique) => (
                <div key={technique.technique_id} className='rounded-md border p-3'>
                  <div className='flex flex-wrap items-center gap-2'>
                    <Badge variant='outline'>{technique.technique_id}</Badge>
                    <p className='font-medium'>{technique.name}</p>
                  </div>
                  <p className='text-muted-foreground mt-1 text-sm'>{technique.reason}</p>
                </div>
              ))
            ) : (
              <p className='text-muted-foreground text-sm'>No ATT&CK techniques mapped yet.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
            <CardDescription>Response actions proposed by the finalizer agent.</CardDescription>
          </CardHeader>
          <CardContent className='space-y-3'>
            {caseFile.recommendations.length > 0 ? (
              caseFile.recommendations.map((recommendation) => (
                <div key={recommendation.id} className='rounded-md border p-3'>
                  <div className='mb-1 flex flex-wrap items-center gap-2'>
                    <SeverityBadge severity={recommendation.priority} />
                    <Badge variant='outline'>{recommendation.status}</Badge>
                  </div>
                  <p className='font-medium'>{recommendation.action}</p>
                  <p className='text-muted-foreground mt-1 text-sm'>{recommendation.rationale}</p>
                </div>
              ))
            ) : (
              <p className='text-muted-foreground text-sm'>No recommendations yet.</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className='grid grid-cols-1 gap-4 lg:grid-cols-2'>
        <Card>
          <CardHeader>
            <CardTitle>Workflow Checkpoints</CardTitle>
            <CardDescription>Persisted snapshots from each workflow node.</CardDescription>
          </CardHeader>
          <CardContent className='space-y-2'>
            {checkpoints.length > 0 ? (
              checkpoints.map((checkpoint) => (
                <div key={checkpoint.id} className='flex items-center justify-between rounded-md border p-3'>
                  <div>
                    <p className='font-medium'>{checkpoint.node_name}</p>
                    <p className='text-muted-foreground text-xs'>
                      {formatDate(checkpoint.created_at)}
                    </p>
                  </div>
                  <StatusBadge status={checkpoint.status} />
                </div>
              ))
            ) : (
              <p className='text-muted-foreground text-sm'>No checkpoints returned yet.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Raw Normalized Alert</CardTitle>
            <CardDescription>The normalized Wazuh payload stored in the case file.</CardDescription>
          </CardHeader>
          <CardContent>
            <JsonBlock value={caseFile.raw_alert} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
