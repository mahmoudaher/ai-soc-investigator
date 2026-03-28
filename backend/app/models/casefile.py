from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Dict, Any, Optional, Literal, Union
from datetime import datetime
import uuid


# Type definitions
Severity = Literal["low", "medium", "high", "critical"]
CaseStatus = Literal["new", "running", "completed", "failed", "escalated"]
EntityType = Literal["host", "user", "ip", "domain", "process", "file", "registry", "url", "email"]
EvidenceType = Literal["log", "nmap", "intel", "note", "pcap", "memory", "network", "file_hash"]


class Entity(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: EntityType
    value: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: EvidenceType
    payload: Dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    source: str  # Which agent/tool collected this
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)

    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v


class TimelineEvent(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    title: str
    description: str
    evidence_ids: List[str] = Field(default_factory=list)
    agent: str  # Which agent created this event
    event_type: Literal["analysis", "detection", "action", "milestone"] = "analysis"


class Hypothesis(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    description: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    supporting_evidence: List[str] = Field(default_factory=list)  # evidence_ids
    status: Literal["active", "confirmed", "rejected", "pending"] = "active"

    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v


class MitreTechnique(BaseModel):
    model_config = ConfigDict(frozen=False)

    technique_id: str
    name: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_ids: List[str]
    reason: str
    tactic: Optional[str] = None
    sub_technique: Optional[str] = None

    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v


class Recommendation(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: str
    priority: Literal["low", "medium", "high", "critical"]
    risk: Literal["low", "medium", "high", "critical"]
    rationale: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: Literal["pending", "approved", "implemented", "rejected"] = "pending"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None


class AgentRun(BaseModel):
    model_config = ConfigDict(frozen=False)

    agent: str
    status: Literal["ok", "error", "timeout", "cancelled"]
    started_at: datetime
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    duration_ms: Optional[int] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost: Optional[float] = None


class CaseFile(BaseModel):
    model_config = ConfigDict(frozen=False)

    # Core identifiers
    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_alert: Dict[str, Any]

    # Status and classification
    status: CaseStatus = "new"
    severity: Optional[Severity] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None

    # Investigation metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    priority: Literal["low", "medium", "high", "critical"] = "medium"

    # Investigation data
    entities: List[Entity] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)

    # Analysis results
    mitre: List[MitreTechnique] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)

    # Execution tracking
    agent_runs: List[AgentRun] = Field(default_factory=list)

    # Summary and notes
    summary: Optional[str] = None
    investigation_notes: List[Dict[str, Any]] = Field(default_factory=list)  # [{timestamp, author, note}]

    def add_entity(self, entity: Entity) -> None:
        """Add entity if it doesn't already exist"""
        if not any(e.value == entity.value and e.type == entity.type for e in self.entities):
            self.entities.append(entity)

    def add_evidence(self, evidence: EvidenceItem) -> None:
        """Add evidence item"""
        self.evidence.append(evidence)

    def add_timeline_event(self, event: TimelineEvent) -> None:
        """Add timeline event"""
        self.timeline.append(event)
        self.updated_at = datetime.utcnow()

    def update_status(self, new_status: CaseStatus) -> None:
        """Update case status and timestamp"""
        self.status = new_status
        self.updated_at = datetime.utcnow()