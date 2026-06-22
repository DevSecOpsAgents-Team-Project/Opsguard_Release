from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, confloat, conlist


class Resource(BaseModel):
    type: str
    id: str
    region: str
    account_id: str


class IncidentSummary(BaseModel):
    source: Literal["guardduty"]
    title: str
    severity: str
    resource: Resource


class EscalationAssessment(BaseModel):
    escalation_needed: bool
    recommended_level: Literal[2, 3]
    confidence: confloat(ge=0.0, le=1.0)
    decision_questions: conlist(str, min_length=1)
    approval_notes: str


class RegulationRef(BaseModel):
    framework: str
    clause_id: str
    clause_title: str = ""
    relevance: confloat(ge=0.0, le=1.0) = 0.5
    excerpt: str = ""
    why_relevant: str = ""


class ActionTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    id: Optional[str] = None
    user_name: Optional[str] = None
    ip: Optional[str] = None
    target_bucket: Optional[str] = None


class PlaybookAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    targets: List[ActionTarget]


class RecommendedPlaybook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: Literal[2, 3]
    playbook_name: str = Field(
        ...,
        description=(
            "Canonical response title (e.g. Credential Containment, Network Isolation). "
            "Not action-level labels."
        ),
    )
    description: str
    actions: conlist(PlaybookAction, min_length=1)
    requires_approval: Literal[True] = True
    expected_impact: Literal["LOW", "MEDIUM", "HIGH"]


class AlternativePlaybook(RecommendedPlaybook):
    """Stronger/weaker tier not chosen as primary."""

    why_not_selected: str = ""


class RegulationAgentIntermediate(BaseModel):
    """LLM / rule-builder output before output-contract split."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.2"]
    generated_at: str
    incident_id: str
    scenario: str

    incident_summary: IncidentSummary
    executed_level1_actions: List[str]

    escalation_assessment: EscalationAssessment
    reasoning_bullets: List[str]

    regulations: List[RegulationRef]
    recommended_actions: List[RecommendedPlaybook]

    insufficient_context: bool
    missing_context_requests: List[str]


class RegulationAgentOutput(BaseModel):
    """Final API contract: primary playbook + alternatives + filtered list."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.3"]
    generated_at: str
    incident_id: str
    scenario: str

    incident_summary: IncidentSummary
    executed_level1_actions: List[str]

    escalation_assessment: EscalationAssessment
    reasoning_bullets: List[str]

    regulations: List[RegulationRef]
    recommended_actions: List[RecommendedPlaybook]
    selected_playbook: Optional[RecommendedPlaybook] = None
    alternative_playbooks: List[AlternativePlaybook] = Field(default_factory=list)

    insufficient_context: bool
    missing_context_requests: List[str]
