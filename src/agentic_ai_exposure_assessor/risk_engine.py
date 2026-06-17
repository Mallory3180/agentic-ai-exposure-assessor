"""The assessment orchestrator.

Loads inventory + runtime evidence from the database into an
:class:`~.rules.base.AssessmentContext`, runs every rule in the catalogue, scores the
resulting findings and persists both the findings and an :class:`~.models.AssessmentRun`
summary.
"""

from __future__ import annotations

import uuid

from sqlmodel import Session, delete, select

from . import models, scoring
from .models import utcnow
from .rules import get_rules
from .rules.base import AssessmentContext
from .schemas import FindingDraft


def build_context(
    session: Session, *, internal_domains: set[str] | None = None
) -> AssessmentContext:
    """Hydrate an :class:`AssessmentContext` from the database."""
    return AssessmentContext(
        agents=list(session.exec(select(models.Agent)).all()),
        users=list(session.exec(select(models.User)).all()),
        tools=list(session.exec(select(models.Tool)).all()),
        permissions=list(session.exec(select(models.Permission)).all()),
        data_sources=list(session.exec(select(models.DataSource)).all()),
        approval_policies=list(session.exec(select(models.ApprovalPolicy)).all()),
        spans=list(session.exec(select(models.RuntimeSpan)).all()),
        tool_calls=list(session.exec(select(models.RuntimeToolCall)).all()),
        messages=list(session.exec(select(models.InterAgentMessage)).all()),
        memory_ops=list(session.exec(select(models.MemoryOperation)).all()),
        internal_domains=internal_domains or set(),
    )


def run_rules(ctx: AssessmentContext) -> list[FindingDraft]:
    """Execute every rule, isolating individual rule failures."""
    drafts: list[FindingDraft] = []
    for rule in get_rules():
        try:
            drafts.extend(rule(ctx))
        except Exception as exc:  # defensive: one bad rule must not abort the run
            drafts.append(
                FindingDraft(
                    rule_id="ENGINE-ERR",
                    title=f"Rule '{getattr(rule, '__name__', rule)}' raised an error",
                    description=f"The rule failed to execute: {exc}",
                    owasp_category="",
                    likelihood=1,
                    impact=1,
                    confidence=1,
                )
            )
    return drafts


def _finalize_finding(draft: FindingDraft, run_id: int) -> models.Finding:
    score = scoring.risk_score(draft.likelihood, draft.impact, draft.confidence)
    return models.Finding(
        finding_id=uuid.uuid4().hex[:12],
        rule_id=draft.rule_id,
        title=draft.title,
        description=draft.description,
        owasp_category=draft.owasp_category,
        severity=scoring.severity_for(score),
        likelihood=scoring.clamp(draft.likelihood),
        impact=scoring.clamp(draft.impact),
        confidence=scoring.clamp(draft.confidence),
        risk_score=score,
        affected_agent=draft.affected_agent,
        affected_tool=draft.affected_tool,
        evidence=draft.evidence,
        remediation=draft.remediation,
        references=draft.references,
        assessment_run_id=run_id,
        created_at=utcnow().isoformat(),
    )


def assess(
    session: Session,
    *,
    run_name: str | None = None,
    config_sources: list[str] | None = None,
    trace_sources: list[str] | None = None,
    internal_domains: set[str] | None = None,
) -> models.AssessmentRun:
    """Run a full assessment and persist findings + run summary."""
    ctx = build_context(session, internal_domains=internal_domains)

    # Clear previous findings (single-run MVP semantics).
    session.exec(delete(models.Finding))
    session.commit()

    run = models.AssessmentRun(
        name=run_name or f"assessment-{utcnow().strftime('%Y%m%d-%H%M%S')}",
        created_at=utcnow().isoformat(),
        config_sources=config_sources or [],
        trace_sources=trace_sources or [],
        total_agents=len(ctx.agents),
        total_tools=len(ctx.tools),
    )
    session.add(run)
    session.commit()
    session.refresh(run)

    drafts = run_rules(ctx)
    findings = [_finalize_finding(d, run.id or 0) for d in drafts]
    for finding in findings:
        session.add(finding)

    run.total_findings = len(findings)
    run.risk_score = scoring.aggregate_run_score(findings)
    run.agent_scores = scoring.aggregate_agent_scores(findings)
    run.owasp_counts = _owasp_counts(findings)
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def _owasp_counts(findings: list[models.Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        if finding.owasp_category:
            counts[finding.owasp_category] = counts.get(finding.owasp_category, 0) + 1
    return counts
