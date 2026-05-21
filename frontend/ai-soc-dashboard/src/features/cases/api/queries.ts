import { queryOptions } from '@tanstack/react-query';
import { getAllCases, getCaseById, getCaseCheckpoints, getCases } from './service';
import type { CaseFilters } from './types';

export const caseKeys = {
  all: ['cases'] as const,
  summary: () => [...caseKeys.all, 'summary'] as const,
  list: (filters: CaseFilters) => [...caseKeys.all, 'list', filters] as const,
  detail: (caseId: string) => [...caseKeys.all, 'detail', caseId] as const,
  checkpoints: (caseId: string) => [...caseKeys.detail(caseId), 'checkpoints'] as const
};

export const caseSummaryQueryOptions = () =>
  queryOptions({
    queryKey: caseKeys.summary(),
    queryFn: () => getAllCases()
  });

export const casesQueryOptions = (filters: CaseFilters) =>
  queryOptions({
    queryKey: caseKeys.list(filters),
    queryFn: () => getCases(filters)
  });

export const caseByIdOptions = (caseId: string) =>
  queryOptions({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCaseById(caseId)
  });

export const caseCheckpointsOptions = (caseId: string) =>
  queryOptions({
    queryKey: caseKeys.checkpoints(caseId),
    queryFn: () => getCaseCheckpoints(caseId)
  });
