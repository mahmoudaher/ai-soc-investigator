'use client';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Icons } from '@/components/icons';
import { useMutation } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { ingestWazuhAlertMutation } from '../api/mutations';

const sampleAlert = {
  id: 'demo-wazuh-4625-001',
  timestamp: '2026-05-20T14:22:00Z',
  rule: {
    id: '60122',
    level: 10,
    description: 'Windows failed logon attempt detected',
    groups: ['windows', 'authentication_failed', 'pci_dss_10.2.4']
  },
  agent: {
    id: '004',
    name: 'WIN11-LAB',
    ip: '192.168.56.21'
  },
  decoder: {
    name: 'windows_eventchannel'
  },
  location: 'EventChannel',
  data: {
    win: {
      eventdata: {
        targetUserName: 'Administrator',
        targetDomainName: 'WIN11-LAB',
        ipAddress: '192.168.56.10',
        processName: 'C:\\Windows\\System32\\svchost.exe'
      }
    }
  },
  full_log:
    'An account failed to log on. Target account: Administrator. Source network address: 192.168.56.10.'
};

export default function CaseIngestForm() {
  const router = useRouter();
  const [payload, setPayload] = useState(JSON.stringify(sampleAlert, null, 2));
  const [runWorkflow, setRunWorkflow] = useState(true);

  const ingestMutation = useMutation({
    ...ingestWazuhAlertMutation,
    onSuccess: (response) => {
      toast.success('Case created from Wazuh alert');
      router.push(`/dashboard/cases/${response.case_id}`);
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : 'Failed to ingest alert');
    }
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Present a New Case</CardTitle>
        <CardDescription>
          Paste a raw Wazuh alert JSON payload. The backend will normalize it, persist the case,
          and optionally run the agent workflow in the background.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className='space-y-5'
          onSubmit={(event) => {
            event.preventDefault();

            try {
              const alert = JSON.parse(payload) as Record<string, unknown>;
              ingestMutation.mutate({ alert, runWorkflow });
            } catch {
              toast.error('Payload must be valid JSON');
            }
          }}
        >
          <div className='space-y-2'>
            <Label htmlFor='wazuh-alert-json'>Wazuh alert JSON</Label>
            <Textarea
              id='wazuh-alert-json'
              value={payload}
              onChange={(event) => setPayload(event.target.value)}
              className='min-h-[420px] font-mono text-xs leading-relaxed'
              spellCheck={false}
            />
          </div>

          <div className='flex flex-col gap-3 rounded-md border p-4 md:flex-row md:items-center md:justify-between'>
            <div>
              <Label htmlFor='run-workflow'>Run investigation workflow</Label>
              <p className='text-muted-foreground mt-1 text-sm'>
                Enable this for the demo flow that moves the case through triage, recon,
                evidence, mapping, and final reporting.
              </p>
            </div>
            <Switch id='run-workflow' checked={runWorkflow} onCheckedChange={setRunWorkflow} />
          </div>

          <div className='flex flex-wrap justify-end gap-2'>
            <Button
              type='button'
              variant='outline'
              onClick={() => setPayload(JSON.stringify(sampleAlert, null, 2))}
            >
              Load sample
            </Button>
            <Button type='submit' disabled={ingestMutation.isPending}>
              {ingestMutation.isPending && <Icons.spinner className='mr-2 h-4 w-4 animate-spin' />}
              Create case
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
