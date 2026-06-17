"""Report assembly and rendering (JSON / Markdown / HTML).

A single :func:`build_report_data` gathers everything from the database into a plain dict
(already redacted at ingest time). The three renderers consume that dict. HTML uses Jinja2
templates under ``templates/``; Markdown is generated directly for tight control of the
required chapter structure.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlmodel import Session, select

from . import graph, models, owasp, redaction, scoring

_TEMPLATE_DIR = Path(__file__).parent / "templates"


# --------------------------------------------------------------------------- #
# Data assembly                                                                #
# --------------------------------------------------------------------------- #
def _latest_run(session: Session) -> models.AssessmentRun | None:
    runs = session.exec(select(models.AssessmentRun)).all()
    return max(runs, key=lambda r: r.id or 0) if runs else None


def build_report_data(session: Session) -> dict[str, Any]:
    """Collect all data needed to render a report."""
    run = _latest_run(session)
    agents = session.exec(select(models.Agent)).all()
    tools = session.exec(select(models.Tool)).all()
    permissions = session.exec(select(models.Permission)).all()
    data_sources = session.exec(select(models.DataSource)).all()
    approval_policies = session.exec(select(models.ApprovalPolicy)).all()
    tool_calls = list(session.exec(select(models.RuntimeToolCall)).all())
    messages = list(session.exec(select(models.InterAgentMessage)).all())
    memory_ops = list(session.exec(select(models.MemoryOperation)).all())
    findings = list(session.exec(select(models.Finding)).all())

    findings.sort(key=lambda f: f.risk_score, reverse=True)

    graphs = graph.trace_graphs(tool_calls, messages)

    # Per-trace ordered sequences.
    sequences: dict[str, list[dict[str, Any]]] = {}
    for call in sorted(tool_calls, key=lambda c: (c.trace_id, c.sequence_index)):
        sequences.setdefault(call.trace_id, []).append(
            {
                "index": call.sequence_index + 1,
                "agent": call.agent_name,
                "tool": call.tool_name,
                "status": call.status,
                "approval_observed": call.approval_observed,
                "approval_status": call.approval_status,
                "credential_scope": call.credential_scope,
                "network_peer": call.network_peer,
                "tls_observed": call.tls_observed,
            }
        )

    severity_counts = scoring.severity_counts(findings)

    owasp_mapping = []
    for category in owasp.ALL_CATEGORIES:
        cat_findings = [f for f in findings if f.owasp_category == category.code]
        owasp_mapping.append(
            {
                "code": category.code,
                "title": category.title,
                "count": len(cat_findings),
                "max_severity": (
                    max((f.severity for f in cat_findings), key=scoring.severity_rank)
                    if cat_findings
                    else "none"
                ),
            }
        )

    high_risk_tools = [
        {"tool_id": t.tool_id, "name": t.name, "category": t.category, "risk_level": t.risk_level}
        for t in tools
        if t.risk_level in {"high", "critical"}
    ]

    unapproved_calls = [
        {"agent": c.agent_name, "tool": c.tool_name, "trace_id": c.trace_id}
        for c in tool_calls
        if not c.approval_observed
        and any(
            (t.tool_id == c.tool_name or t.name == c.tool_name) and t.requires_approval
            for t in tools
        )
    ]

    known_agent_names = {a.agent_id for a in agents} | {a.name for a in agents}
    unknown_agents = sorted(
        {c.agent_name for c in tool_calls if c.agent_name and c.agent_name not in known_agent_names}
    )
    known_tool_names = {t.tool_id for t in tools} | {t.name for t in tools}
    unknown_tools = sorted(
        {c.tool_name for c in tool_calls if c.tool_name and c.tool_name not in known_tool_names}
    )

    return {
        "run": _run_dict(run),
        "agents": [_agent_dict(a) for a in agents],
        "tools": [_tool_dict(t) for t in tools],
        "permissions": [_perm_dict(p) for p in permissions],
        "data_sources": [_ds_dict(d) for d in data_sources],
        "approval_policies": [_policy_dict(p) for p in approval_policies],
        "sequences": sequences,
        "graphs": graphs,
        "messages": [_message_dict(m) for m in messages],
        "memory_ops": [_memory_dict(m) for m in memory_ops],
        "findings": [_finding_dict(f) for f in findings],
        "severity_counts": severity_counts,
        "owasp_mapping": owasp_mapping,
        "high_risk_tools": high_risk_tools,
        "unapproved_calls": unapproved_calls,
        "unknown_agents": unknown_agents,
        "unknown_tools": unknown_tools,
        "agent_scores": run.agent_scores if run else {},
    }


def _run_dict(run: models.AssessmentRun | None) -> dict[str, Any]:
    if run is None:
        return {
            "name": "(no assessment run yet)",
            "created_at": "",
            "total_agents": 0,
            "total_tools": 0,
            "total_findings": 0,
            "risk_score": 0,
            "config_sources": [],
            "trace_sources": [],
        }
    return {
        "name": run.name,
        "created_at": run.created_at,
        "total_agents": run.total_agents,
        "total_tools": run.total_tools,
        "total_findings": run.total_findings,
        "risk_score": run.risk_score,
        "config_sources": run.config_sources,
        "trace_sources": run.trace_sources,
    }


def _agent_dict(a: models.Agent) -> dict[str, Any]:
    return {
        "agent_id": a.agent_id,
        "name": a.name,
        "owner": a.owner,
        "environment": a.environment,
        "platform": a.platform,
        "model": f"{a.model_provider}/{a.model_name}".strip("/"),
        "public_exposure": a.public_exposure,
        "trust_level": a.trust_level,
        "allowed_tools": a.allowed_tools,
        "connected_data_sources": a.connected_data_sources,
        "connected_mcp_servers": a.connected_mcp_servers,
    }


def _tool_dict(t: models.Tool) -> dict[str, Any]:
    return {
        "tool_id": t.tool_id,
        "name": t.name,
        "category": t.category,
        "risk_level": t.risk_level,
        "requires_approval": t.requires_approval,
        "allowed_scopes": t.allowed_scopes,
        "sandbox_required": t.sandbox_required,
    }


def _perm_dict(p: models.Permission) -> dict[str, Any]:
    return {
        "principal_type": p.principal_type,
        "principal_id": p.principal_id,
        "tool_id": p.tool_id,
        "scope": p.scope,
        "permission_level": p.permission_level,
    }


def _ds_dict(d: models.DataSource) -> dict[str, Any]:
    return {
        "name": d.name,
        "type": d.type,
        "classification": d.classification,
        "contains_pii": d.contains_pii,
        "trust": d.trust,
        "connected_agents": d.connected_agents,
    }


def _policy_dict(p: models.ApprovalPolicy) -> dict[str, Any]:
    return {
        "tool_id": p.tool_id,
        "required": p.required,
        "approver_role": p.approver_role,
        "condition": p.condition,
        "bypass_allowed": p.bypass_allowed,
    }


def _message_dict(m: models.InterAgentMessage) -> dict[str, Any]:
    return {
        "source_agent": m.source_agent,
        "destination_agent": m.destination_agent,
        "message_type": m.message_type,
        "transport": m.transport,
        "tls_observed": m.tls_observed,
        "mtls_observed": m.mtls_observed,
    }


def _memory_dict(m: models.MemoryOperation) -> dict[str, Any]:
    return {
        "agent_name": m.agent_name,
        "operation": m.operation,
        "source": m.source,
        "source_trust": m.source_trust,
        "sanitized": m.sanitized,
    }


def _finding_dict(f: models.Finding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "rule_id": f.rule_id,
        "title": f.title,
        "description": f.description,
        "owasp_category": f.owasp_category,
        "owasp_title": owasp.title_for(f.owasp_category),
        "severity": f.severity,
        "likelihood": f.likelihood,
        "impact": f.impact,
        "confidence": f.confidence,
        "risk_score": f.risk_score,
        "affected_agent": f.affected_agent,
        "affected_tool": f.affected_tool,
        "evidence": redaction.redact_value(f.evidence),
        "remediation": f.remediation,
        "references": f.references,
    }


# --------------------------------------------------------------------------- #
# Renderers                                                                    #
# --------------------------------------------------------------------------- #
def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") for c in row]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def render_markdown(data: dict[str, Any]) -> str:
    run = data["run"]
    lines: list[str] = []
    lines.append("# Agentic AI Exposure Assessment Report")
    lines.append("")
    lines.append(f"_Run: **{run['name']}**  |  Generated: {run['created_at']}_")
    lines.append("")

    # 1. Executive Summary
    lines.append("## 1. Executive Summary")
    lines.append("")
    sev = data["severity_counts"]
    lines.append(
        f"- Total agents: **{run['total_agents']}**, tools: **{run['total_tools']}**, "
        f"findings: **{run['total_findings']}**"
    )
    lines.append(f"- Aggregate risk score: **{run['risk_score']}**")
    lines.append(
        "- Findings by severity: "
        + ", ".join(f"{k}={v}" for k, v in sev.items() if v or k in {"critical", "high"})
    )
    lines.append("")

    # 2. Scope
    lines.append("## 2. Scope")
    lines.append("")
    lines.append(f"- Config sources: {', '.join(run['config_sources']) or '(none)'}")
    lines.append(f"- Trace sources: {', '.join(run['trace_sources']) or '(none)'}")
    lines.append("")

    # 3. Agent Inventory
    lines.append("## 3. Agent Inventory")
    lines.append("")
    lines.append(
        _md_table(
            ["Agent", "Owner", "Exposure", "Trust", "Model", "Allowed Tools", "Risk Score"],
            [
                [
                    a["agent_id"],
                    a["owner"] or "(none)",
                    a["public_exposure"],
                    a["trust_level"],
                    a["model"],
                    ", ".join(a["allowed_tools"]) or "-",
                    data["agent_scores"].get(a["agent_id"], 0),
                ]
                for a in data["agents"]
            ],
        )
    )
    lines.append("")

    # 4. Tool and Permission Matrix
    lines.append("## 4. Tool and Permission Matrix")
    lines.append("")
    lines.append("### Tools")
    lines.append("")
    lines.append(
        _md_table(
            ["Tool", "Category", "Risk", "Requires Approval", "Sandbox", "Allowed Scopes"],
            [
                [
                    t["tool_id"],
                    t["category"],
                    t["risk_level"],
                    t["requires_approval"],
                    t["sandbox_required"],
                    ", ".join(t["allowed_scopes"]) or "-",
                ]
                for t in data["tools"]
            ],
        )
    )
    lines.append("")
    lines.append("### Permissions")
    lines.append("")
    lines.append(
        _md_table(
            ["Principal", "Type", "Tool", "Scope", "Level"],
            [
                [
                    p["principal_id"],
                    p["principal_type"],
                    p["tool_id"],
                    p["scope"],
                    p["permission_level"],
                ]
                for p in data["permissions"]
            ],
        )
    )
    lines.append("")

    # 5. Runtime Trace Analysis
    lines.append("## 5. Runtime Trace Analysis")
    lines.append("")
    for trace_id, seq in data["sequences"].items():
        lines.append(f"### Trace `{trace_id}`")
        lines.append("")
        lines.append(
            _md_table(
                ["#", "Agent", "Tool", "Status", "Approval", "Scope", "TLS"],
                [
                    [
                        s["index"],
                        s["agent"],
                        s["tool"],
                        s["status"],
                        "observed" if s["approval_observed"] else (s["approval_status"] or "none"),
                        s["credential_scope"] or "-",
                        "yes" if s["tls_observed"] else "no",
                    ]
                    for s in seq
                ],
            )
        )
        lines.append("")
        graphs = data["graphs"].get(trace_id, {})
        if graphs.get("tool_sequence"):
            lines.append("```mermaid")
            lines.append(graphs["tool_sequence"])
            lines.append("```")
            lines.append("")
        if graphs.get("inter_agent"):
            lines.append("```mermaid")
            lines.append(graphs["inter_agent"])
            lines.append("```")
            lines.append("")

    # 6. Approval Gate Analysis
    lines.append("## 6. Approval Gate Analysis")
    lines.append("")
    if data["unapproved_calls"]:
        lines.append(
            _md_table(
                ["Agent", "Tool", "Trace"],
                [[c["agent"], c["tool"], c["trace_id"]] for c in data["unapproved_calls"]],
            )
        )
    else:
        lines.append("_No approval-required tools were executed without approval._")
    lines.append("")

    # 7. OWASP Mapping
    lines.append("## 7. OWASP Agentic AI Top 10 Risk Mapping")
    lines.append("")
    lines.append(
        _md_table(
            ["Code", "Category", "Findings", "Max Severity"],
            [[m["code"], m["title"], m["count"], m["max_severity"]] for m in data["owasp_mapping"]],
        )
    )
    lines.append("")

    # 8. Findings
    lines.append("## 8. Findings")
    lines.append("")
    for f in data["findings"]:
        lines.append(f"### [{f['severity'].upper()}] {f['title']}")
        lines.append("")
        lines.append(
            f"- **OWASP**: {f['owasp_category']} {f['owasp_title']}  |  "
            f"**Rule**: {f['rule_id']}  |  **Risk score**: {f['risk_score']} "
            f"(L{f['likelihood']} x I{f['impact']} x C{f['confidence']})"
        )
        if f["affected_agent"]:
            lines.append(f"- **Affected agent**: {f['affected_agent']}")
        if f["affected_tool"]:
            lines.append(f"- **Affected tool**: {f['affected_tool']}")
        lines.append(f"- **Description**: {f['description']}")
        lines.append(f"- **Remediation**: {f['remediation']}")
        lines.append("")

    # 9. Recommendations
    lines.append("## 9. Recommendations")
    lines.append("")
    for rec in _recommendations(data):
        lines.append(f"- {rec}")
    lines.append("")

    # 10. Appendix: Evidence
    lines.append("## 10. Appendix: Evidence")
    lines.append("")
    for f in data["findings"]:
        lines.append(f"#### {f['finding_id']} - {f['rule_id']}")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(f["evidence"], indent=2, ensure_ascii=False))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def _recommendations(data: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    if data["unapproved_calls"]:
        recs.append("Enforce human approval gates before approval-required tools execute.")
    if data["unknown_agents"]:
        recs.append("Inventory or block unmanaged agents observed at runtime.")
    if data["unknown_tools"]:
        recs.append("Register or block tools invoked at runtime that are not in the registry.")
    if any(m["code"] == owasp.ASI03.code and m["count"] for m in data["owasp_mapping"]):
        recs.append("Apply least-privilege scopes and align permission levels to tool risk.")
    if any(m["code"] == owasp.ASI07.code and m["count"] for m in data["owasp_mapping"]):
        recs.append("Enforce TLS/mTLS on all inter-agent communication.")
    if not recs:
        recs.append("No systemic issues detected in this run; maintain monitoring.")
    return recs


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_html(data: dict[str, Any]) -> str:
    env = _jinja_env()
    template = env.get_template("report.html")
    return template.render(data=data)


# --------------------------------------------------------------------------- #
# File output                                                                  #
# --------------------------------------------------------------------------- #
def export(session: Session, fmt: str, output: Path) -> Path:
    """Build + render a report and write it to ``output`` (creating parent dirs)."""
    data = build_report_data(session)
    fmt = fmt.lower()
    if fmt == "json":
        content = render_json(data)
    elif fmt in {"md", "markdown"}:
        content = render_markdown(data)
    elif fmt == "html":
        content = render_html(data)
    else:
        raise ValueError(f"Unsupported report format: {fmt!r} (use json/markdown/html)")

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output
