export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type CaseStatus = 'new' | 'running' | 'completed' | 'failed' | 'escalated';
export type EntityType =
  | 'host'
  | 'user'
  | 'ip'
  | 'domain'
  | 'process'
  | 'file'
  | 'registry'
  | 'url'
  | 'email';
export type EvidenceType =
  | 'log'
  | 'nmap'
  | 'intel'
  | 'note'
  | 'pcap'
  | 'memory'
  | 'network'
  | 'file_hash';

export type Entity = {
  id: string;
  type: EntityType;
  value: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
};

export type EvidenceItem = {
  id: string;
  type: EvidenceType;
  payload: Record<string, unknown>;
  created_at: string;
  source: string;
  confidence: number;
  tags: string[];
};

export type TimelineEvent = {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  evidence_ids: string[];
  agent: string;
  event_type: 'analysis' | 'detection' | 'action' | 'milestone';
};

export type TriagePlanStep = {
  entity_type?: EntityType | null;
  entity_value?: string | null;
  goal: string;
  rationale: string;
  priority: Severity;
};

export type TriageAssessment = {
  summary: string;
  confidence: number;
  plan: TriagePlanStep[];
};

export type Hypothesis = {
  id: string;
  description: string;
  confidence: number;
  created_at: string;
  supporting_evidence: string[];
  status: 'active' | 'confirmed' | 'rejected' | 'pending';
};

export type MitreTechnique = {
  technique_id: string;
  name: string;
  confidence: number;
  evidence_ids: string[];
  reason: string;
  tactic?: string | null;
  sub_technique?: string | null;
};

export type Recommendation = {
  id: string;
  action: string;
  priority: Severity;
  risk: Severity;
  rationale: string;
  created_at: string;
  status: 'pending' | 'approved' | 'implemented' | 'rejected';
  assigned_to?: string | null;
  due_date?: string | null;
};

export type AgentRun = {
  agent: string;
  status: 'ok' | 'error' | 'timeout' | 'cancelled' | 'error_no_key';
  started_at: string;
  finished_at?: string | null;
  error?: string | null;
  duration_ms?: number | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  cost?: number | null;
};

export type CaseFile = {
  case_id: string;
  raw_alert: Record<string, unknown>;
  source?: string | null;
  status: CaseStatus;
  severity?: Severity | null;
  category?: string | null;
  subcategory?: string | null;
  triage?: TriageAssessment | null;
  created_at: string;
  updated_at: string;
  assigned_to?: string | null;
  tags: string[];
  priority: Severity;
  entities: Entity[];
  evidence: EvidenceItem[];
  timeline: TimelineEvent[];
  hypotheses: Hypothesis[];
  mitre: MitreTechnique[];
  recommendations: Recommendation[];
  agent_runs: AgentRun[];
  summary?: string | null;
  investigation_notes: Record<string, unknown>[];
};

export type CaseCheckpoint = {
  id: number;
  case_id: string;
  node_name: string;
  status: CaseStatus;
  severity?: Severity | null;
  category?: string | null;
  case_file: CaseFile;
  created_at: string;
};

export type CaseFilters = {
  page?: number;
  limit?: number;
  search?: string;
  status?: string;
  severity?: string;
  sort?: string;
};

export type CasesResponse = {
  success: boolean;
  time: string;
  total_cases: number;
  offset: number;
  limit: number;
  cases: CaseFile[];
};

export type CaseByIdResponse = {
  success: boolean;
  time: string;
  case_file: CaseFile;
};

export type CheckpointsResponse = {
  success: boolean;
  time: string;
  checkpoints: CaseCheckpoint[];
};

export type IngestAlertResponse = {
  case_id: string;
  status: CaseStatus;
  severity?: Severity | null;
  category?: string | null;
  case_file: CaseFile;
};

export type IngestAlertPayload = {
  alert: Record<string, unknown>;
  runWorkflow: boolean;
};
