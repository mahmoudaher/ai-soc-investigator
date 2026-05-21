import { apiClient } from '@/lib/api-client';
import type {
  CaseByIdResponse,
  CaseCheckpoint,
  CaseFile,
  CaseFilters,
  CasesResponse,
  CheckpointsResponse,
  IngestAlertPayload,
  IngestAlertResponse
} from './types';

const DEFAULT_CASE_LIMIT = 200;

const severityRank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

function includesAny(value: string | null | undefined, selected?: string) {
  if (!selected) return true;
  const values = selected.split(',').filter(Boolean);
  if (values.length === 0) return true;
  return value ? values.includes(value) : false;
}

function caseSearchText(caseFile: CaseFile) {
  return [
    caseFile.case_id,
    caseFile.status,
    caseFile.severity,
    caseFile.category,
    caseFile.subcategory,
    caseFile.source,
    caseFile.summary,
    caseFile.assigned_to,
    caseFile.tags.join(' '),
    ...caseFile.entities.map((entity) => `${entity.type} ${entity.value}`)
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function parseSort(sort?: string): { id: string; desc: boolean } | null {
  if (!sort) return null;

  try {
    const parsed = JSON.parse(sort) as { id: string; desc: boolean }[];
    return parsed[0] ?? null;
  } catch {
    return null;
  }
}

function compareCases(a: CaseFile, b: CaseFile, sort?: string) {
  const parsedSort = parseSort(sort);
  const id = parsedSort?.id ?? 'updated_at';
  const direction = parsedSort?.desc ?? true ? -1 : 1;

  const valueA = getComparableValue(a, id);
  const valueB = getComparableValue(b, id);

  if (valueA < valueB) return -1 * direction;
  if (valueA > valueB) return 1 * direction;
  return 0;
}

function getComparableValue(caseFile: CaseFile, id: string) {
  switch (id) {
    case 'severity':
      return severityRank[caseFile.severity ?? ''] ?? 0;
    case 'entities':
      return caseFile.entities.length;
    case 'evidence':
      return caseFile.evidence.length;
    case 'status':
      return caseFile.status;
    case 'category':
      return caseFile.category ?? '';
    case 'created_at':
      return new Date(caseFile.created_at).getTime();
    case 'updated_at':
    default:
      return new Date(caseFile.updated_at).getTime();
  }
}

export async function getCases(filters: CaseFilters = {}): Promise<CasesResponse> {
  const page = filters.page ?? 1;
  const limit = filters.limit ?? 10;
  const backendLimit = Math.max(DEFAULT_CASE_LIMIT, limit);
  const cases = await apiClient<CaseFile[]>(`/cases?limit=${backendLimit}`);
  const search = filters.search?.trim().toLowerCase();

  const filteredCases = cases
    .filter((caseFile) => includesAny(caseFile.status, filters.status))
    .filter((caseFile) => includesAny(caseFile.severity, filters.severity))
    .filter((caseFile) => (search ? caseSearchText(caseFile).includes(search) : true))
    .toSorted((a, b) => compareCases(a, b, filters.sort));

  const offset = (page - 1) * limit;

  return {
    success: true,
    time: new Date().toISOString(),
    total_cases: filteredCases.length,
    offset,
    limit,
    cases: filteredCases.slice(offset, offset + limit)
  };
}

export async function getAllCases(limit = DEFAULT_CASE_LIMIT) {
  return apiClient<CaseFile[]>(`/cases?limit=${limit}`);
}

export async function getCaseById(caseId: string): Promise<CaseByIdResponse> {
  const caseFile = await apiClient<CaseFile>(`/cases/${encodeURIComponent(caseId)}`);

  return {
    success: true,
    time: new Date().toISOString(),
    case_file: caseFile
  };
}

export async function getCaseCheckpoints(caseId: string): Promise<CheckpointsResponse> {
  const checkpoints = await apiClient<CaseCheckpoint[]>(
    `/cases/${encodeURIComponent(caseId)}/checkpoints?limit=100`
  );

  return {
    success: true,
    time: new Date().toISOString(),
    checkpoints
  };
}

export async function ingestWazuhAlert({
  alert,
  runWorkflow
}: IngestAlertPayload): Promise<IngestAlertResponse> {
  return apiClient<IngestAlertResponse>(
    `/alerts/wazuh?run_workflow=${encodeURIComponent(String(runWorkflow))}`,
    {
      method: 'POST',
      body: JSON.stringify(alert)
    }
  );
}
