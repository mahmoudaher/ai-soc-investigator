import { mutationOptions } from '@tanstack/react-query';
import { getQueryClient } from '@/lib/query-client';
import { ingestWazuhAlert } from './service';
import { caseKeys } from './queries';
import type { IngestAlertPayload } from './types';

export const ingestWazuhAlertMutation = mutationOptions({
  mutationFn: (payload: IngestAlertPayload) => ingestWazuhAlert(payload),
  onSuccess: () => {
    getQueryClient().invalidateQueries({ queryKey: caseKeys.all });
  }
});
