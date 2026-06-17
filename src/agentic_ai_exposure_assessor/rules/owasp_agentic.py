"""OWASP Top 10 for Agentic Applications 2026 rules.

Each rule is a small pure function over the :class:`AssessmentContext`. Rules are grouped
by ASI category. The catalogue at the bottom (:data:`ALL_RULES`) is what the risk engine
executes; adding a rule is just appending a function there.
"""

from __future__ import annotations

from .. import owasp
from ..schemas import FindingDraft
from .base import AssessmentContext, scan_dangerous_arguments

_OWASP_REF = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"

_HIGH_RISK_CATEGORIES = {"shell", "code_execution", "file_system", "payment", "identity"}
_CODE_EXEC_CATEGORIES = {"shell", "code_execution", "file_system"}


# --------------------------------------------------------------------------- #
# ASI02 — Tool Misuse and Exploitation                                         #
# --------------------------------------------------------------------------- #
def rule_tool_not_in_allowed_list(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        agent = ctx.agent_for(call.agent_name)
        if agent is None:
            continue  # unknown agent handled by ASI10
        allowed = set(agent.allowed_tools)
        tool = ctx.tool_for(call.tool_name)
        names = {call.tool_name}
        if tool:
            names |= {tool.tool_id, tool.name}
        if allowed and not (names & allowed):
            findings.append(
                FindingDraft(
                    rule_id="ASI02-001",
                    title=f"Agent '{call.agent_name}' executed tool "
                    f"'{call.tool_name}' not in its allowed_tools",
                    description="A tool was invoked at runtime that is not part of the "
                    "agent's design-time allowed tool list, indicating tool misuse or a "
                    "broken authorization boundary.",
                    owasp_category=owasp.ASI02.code,
                    likelihood=4,
                    impact=4,
                    confidence=4,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={
                        "trace_id": call.trace_id,
                        "span_id": call.span_id,
                        "allowed_tools": sorted(allowed),
                        "observed_tool": call.tool_name,
                    },
                    remediation="Restrict the agent's runtime tool access to its approved "
                    "allowed_tools, or update the design if the tool is legitimately needed.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_unknown_tool_executed(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        if ctx.tool_for(call.tool_name) is None:
            findings.append(
                FindingDraft(
                    rule_id="ASI02-002",
                    title=f"Unknown tool '{call.tool_name}' executed (not in tool registry)",
                    description="A tool invoked at runtime is not present in the tool "
                    "registry, so its risk level, scopes and approval requirements are "
                    "unmanaged.",
                    owasp_category=owasp.ASI02.code,
                    likelihood=4,
                    impact=3,
                    confidence=4,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={"trace_id": call.trace_id, "span_id": call.span_id},
                    remediation="Register the tool in tool_registry.yml with an explicit "
                    "risk_level, allowed_scopes and approval policy, or block it.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_dangerous_arguments(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        tool = ctx.tool_for(call.tool_name)
        risk = tool.risk_level if tool else "high"
        if risk not in {"high", "critical"} and tool is not None:
            # Still scan, but only emit for medium+ to limit noise.
            if risk == "low":
                continue
        signals = scan_dangerous_arguments(
            call.arguments, internal_domains=ctx.internal_domains
        )
        if not signals:
            continue
        kinds = sorted({s.kind for s in signals})
        findings.append(
            FindingDraft(
                rule_id="ASI02-003",
                title=f"Dangerous arguments passed to '{call.tool_name}': {', '.join(kinds)}",
                description="High-risk tool invocation contained potentially dangerous "
                "argument values (shell tokens, external URLs, file paths, credential-like "
                "strings, SQL writes or external email recipients).",
                owasp_category=owasp.ASI02.code,
                likelihood=3,
                impact=4,
                confidence=3,
                affected_agent=call.agent_name,
                affected_tool=call.tool_name,
                evidence={
                    "trace_id": call.trace_id,
                    "span_id": call.span_id,
                    "signals": [{"kind": s.kind, "detail": s.detail} for s in signals],
                },
                remediation="Validate and constrain tool arguments; apply allow-lists for "
                "URLs, paths and recipients, and never pass credentials as tool arguments.",
                references=[_OWASP_REF],
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# ASI03 — Identity and Privilege Abuse                                         #
# --------------------------------------------------------------------------- #
_BROAD_SCOPES = {"*", "all", "full_access", "admin", "*.*", "mail.*", "files.*"}
_LEVEL_RANK = {"read": 1, "write": 2, "admin": 3}
_RISK_MAX_LEVEL = {"low": 1, "medium": 2, "high": 3, "critical": 3}


def rule_overbroad_scope(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for perm in ctx.permissions:
        scope = (perm.scope or "").lower()
        if scope in _BROAD_SCOPES or scope.endswith(".*") or scope == "*":
            findings.append(
                FindingDraft(
                    rule_id="ASI03-001",
                    title=f"Over-broad permission scope '{perm.scope}' granted to "
                    f"{perm.principal_type} '{perm.principal_id}'",
                    description="A wildcard or otherwise excessively broad scope is granted, "
                    "violating least privilege.",
                    owasp_category=owasp.ASI03.code,
                    likelihood=3,
                    impact=4,
                    confidence=4,
                    affected_agent=perm.principal_id,
                    affected_tool=perm.tool_id,
                    evidence={"scope": perm.scope, "permission_level": perm.permission_level},
                    remediation="Replace wildcard scopes with the minimal specific scopes the "
                    "agent actually needs.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_excessive_permission_level(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for perm in ctx.permissions:
        tool = ctx.tool_for(perm.tool_id)
        if tool is None:
            continue
        granted = _LEVEL_RANK.get(perm.permission_level, 1)
        allowed_max = _RISK_MAX_LEVEL.get(tool.risk_level, 3)
        if tool.risk_level == "low" and granted > 1:
            findings.append(
                FindingDraft(
                    rule_id="ASI03-002",
                    title=f"Permission level '{perm.permission_level}' on low-risk tool "
                    f"'{tool.tool_id}' is excessive",
                    description="A write/admin permission is granted on a tool whose risk "
                    "level does not justify it.",
                    owasp_category=owasp.ASI03.code,
                    likelihood=2,
                    impact=3,
                    confidence=3,
                    affected_agent=perm.principal_id,
                    affected_tool=perm.tool_id,
                    evidence={
                        "tool_risk_level": tool.risk_level,
                        "permission_level": perm.permission_level,
                    },
                    remediation="Lower the permission level to match the tool's risk profile.",
                    references=[_OWASP_REF],
                )
            )
        elif granted > allowed_max:
            findings.append(
                FindingDraft(
                    rule_id="ASI03-002",
                    title=f"Permission level '{perm.permission_level}' exceeds tool "
                    f"'{tool.tool_id}' risk ceiling",
                    description="Granted permission level is higher than appropriate for the "
                    "tool's risk classification.",
                    owasp_category=owasp.ASI03.code,
                    likelihood=2,
                    impact=3,
                    confidence=3,
                    affected_agent=perm.principal_id,
                    affected_tool=perm.tool_id,
                    evidence={
                        "tool_risk_level": tool.risk_level,
                        "permission_level": perm.permission_level,
                    },
                    remediation="Align permission_level with the tool risk ceiling.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_scope_not_allowed(ctx: AssessmentContext) -> list[FindingDraft]:
    """Tool executed with a credential scope outside the tool's allowed_scopes."""
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        if not call.credential_scope:
            continue
        tool = ctx.tool_for(call.tool_name)
        if tool is None or not tool.allowed_scopes:
            continue
        if call.credential_scope not in tool.allowed_scopes:
            findings.append(
                FindingDraft(
                    rule_id="ASI03-003",
                    title=f"Tool '{call.tool_name}' executed with scope "
                    f"'{call.credential_scope}' not in allowed_scopes",
                    description="Runtime credential scope does not match the tool's declared "
                    "allowed_scopes, indicating privilege drift or token misuse.",
                    owasp_category=owasp.ASI03.code,
                    likelihood=3,
                    impact=4,
                    confidence=4,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={
                        "trace_id": call.trace_id,
                        "observed_scope": call.credential_scope,
                        "allowed_scopes": tool.allowed_scopes,
                    },
                    remediation="Issue tokens scoped to the tool's allowed_scopes only and "
                    "reject mismatched scopes at runtime.",
                    references=[_OWASP_REF],
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# ASI05 — Unexpected or Unauthorized Code Execution                            #
# --------------------------------------------------------------------------- #
def rule_code_exec_without_approval(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        tool = ctx.tool_for(call.tool_name)
        category = tool.category if tool else ""
        if category in _CODE_EXEC_CATEGORIES and not call.approval_observed:
            findings.append(
                FindingDraft(
                    rule_id="ASI05-001",
                    title=f"Code-execution tool '{call.tool_name}' ran without approval",
                    description=f"A '{category}' category tool executed without an observed "
                    "human approval, allowing potentially unauthorized code execution.",
                    owasp_category=owasp.ASI05.code,
                    likelihood=4,
                    impact=5,
                    confidence=4,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={
                        "trace_id": call.trace_id,
                        "span_id": call.span_id,
                        "category": category,
                        "approval_status": call.approval_status,
                    },
                    remediation="Require and enforce human approval (or sandboxing) before any "
                    "shell / code-execution / file-system tool runs.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_sandbox_missing(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        tool = ctx.tool_for(call.tool_name)
        if tool is None or not tool.sandbox_required:
            continue
        span = next((s for s in ctx.spans if s.span_id == call.span_id), None)
        attrs = span.attributes if span else {}
        sandbox_evidence = any(
            str(k).startswith("sandbox") and attrs.get(k) for k in attrs
        )
        if not sandbox_evidence:
            findings.append(
                FindingDraft(
                    rule_id="ASI05-002",
                    title=f"Tool '{call.tool_name}' requires a sandbox but none observed",
                    description="The tool is marked sandbox_required=true yet no sandbox "
                    "evidence (sandbox.* attribute) was found on the runtime span.",
                    owasp_category=owasp.ASI05.code,
                    likelihood=3,
                    impact=4,
                    confidence=3,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={"trace_id": call.trace_id, "span_id": call.span_id},
                    remediation="Execute the tool inside an enforced sandbox and emit a "
                    "sandbox.* attribute as evidence.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_dangerous_command_pattern(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        tool = ctx.tool_for(call.tool_name)
        category = tool.category if tool else ""
        if category not in _CODE_EXEC_CATEGORIES and category != "":
            continue
        signals = [
            s
            for s in scan_dangerous_arguments(call.arguments, internal_domains=ctx.internal_domains)
            if s.kind in {"shell_command", "file_path", "external_url"}
        ]
        if signals:
            findings.append(
                FindingDraft(
                    rule_id="ASI05-003",
                    title=f"Dangerous command pattern in '{call.tool_name}' arguments",
                    description="Code-execution tool received arguments matching dangerous "
                    "command / path / URL patterns.",
                    owasp_category=owasp.ASI05.code,
                    likelihood=3,
                    impact=4,
                    confidence=3,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={
                        "trace_id": call.trace_id,
                        "signals": [{"kind": s.kind, "detail": s.detail} for s in signals],
                    },
                    remediation="Sanitize and allow-list command arguments before execution.",
                    references=[_OWASP_REF],
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# ASI06 — Memory, RAG, and Context Poisoning                                   #
# --------------------------------------------------------------------------- #
def rule_untrusted_memory_write(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for op in ctx.memory_ops:
        if op.operation == "write" and op.source_trust == "untrusted":
            findings.append(
                FindingDraft(
                    rule_id="ASI06-001",
                    title=f"Untrusted content written to memory by '{op.agent_name}'",
                    description="A memory write originates from an untrusted source, enabling "
                    "memory poisoning that can influence future agent behavior.",
                    owasp_category=owasp.ASI06.code,
                    likelihood=4,
                    impact=4,
                    confidence=3,
                    affected_agent=op.agent_name,
                    evidence={
                        "trace_id": op.trace_id,
                        "source": op.source,
                        "source_trust": op.source_trust,
                    },
                    remediation="Validate, attribute and sanitize content before writing it "
                    "to long-term memory; isolate untrusted memory.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_unsanitized_rag(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for op in ctx.memory_ops:
        if op.operation == "read" or op.rag_query:
            if op.source_trust == "untrusted" and not op.sanitized:
                findings.append(
                    FindingDraft(
                        rule_id="ASI06-002",
                        title=f"Untrusted RAG context used without sanitization by "
                        f"'{op.agent_name}'",
                        description="External / user-supplied content was used as RAG context "
                        "without sanitization evidence, enabling context poisoning.",
                        owasp_category=owasp.ASI06.code,
                        likelihood=3,
                        impact=4,
                        confidence=3,
                        affected_agent=op.agent_name,
                        evidence={
                            "trace_id": op.trace_id,
                            "source": op.source,
                            "sanitized": op.sanitized,
                        },
                        remediation="Sanitize and provenance-tag retrieved content; emit a "
                        "sanitization.applied attribute.",
                        references=[_OWASP_REF],
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# ASI07 — Insecure Inter-Agent Communication                                   #
# --------------------------------------------------------------------------- #
def rule_missing_tls(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for msg in ctx.messages:
        if not msg.tls_observed:
            findings.append(
                FindingDraft(
                    rule_id="ASI07-001",
                    title=f"Inter-agent message {msg.source_agent} -> "
                    f"{msg.destination_agent} without TLS",
                    description="No tls.protocol.name was observed on an inter-agent message, "
                    "so the channel may be unencrypted.",
                    owasp_category=owasp.ASI07.code,
                    likelihood=3,
                    impact=4,
                    confidence=4,
                    affected_agent=msg.source_agent,
                    evidence={
                        "trace_id": msg.trace_id,
                        "destination": msg.destination_agent,
                        "network_peer": msg.network_peer,
                    },
                    remediation="Enforce TLS (ideally mTLS) for all inter-agent transports.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_trust_downgrade(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for msg in ctx.messages:
        src = ctx.agent_for(msg.source_agent)
        dst = ctx.agent_for(msg.destination_agent)
        if src and dst and src.trust_level == "high" and dst.trust_level == "low":
            findings.append(
                FindingDraft(
                    rule_id="ASI07-002",
                    title=f"Data flows from high-trust '{msg.source_agent}' to low-trust "
                    f"'{msg.destination_agent}'",
                    description="A high-trust agent passes data to a low-trust agent, which "
                    "can leak sensitive context across a trust boundary.",
                    owasp_category=owasp.ASI07.code,
                    likelihood=3,
                    impact=4,
                    confidence=3,
                    affected_agent=msg.source_agent,
                    evidence={
                        "trace_id": msg.trace_id,
                        "source_trust": src.trust_level,
                        "destination_trust": dst.trust_level,
                    },
                    remediation="Apply data minimization and filtering when crossing trust "
                    "boundaries between agents.",
                    references=[_OWASP_REF],
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# ASI08 — Cascading Failures and Uncontrolled Autonomy                         #
# --------------------------------------------------------------------------- #
def rule_too_many_tool_calls(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    counts: dict[str, int] = {}
    for call in ctx.tool_calls:
        counts[call.trace_id] = counts.get(call.trace_id, 0) + 1
    for trace_id, count in counts.items():
        if count > ctx.max_tool_calls_per_trace:
            findings.append(
                FindingDraft(
                    rule_id="ASI08-001",
                    title=f"Trace {trace_id[:12]} exceeded tool-call budget "
                    f"({count} > {ctx.max_tool_calls_per_trace})",
                    description="An unusually high number of tool calls in a single trace "
                    "suggests uncontrolled autonomy or a runaway loop.",
                    owasp_category=owasp.ASI08.code,
                    likelihood=3,
                    impact=3,
                    confidence=3,
                    evidence={"trace_id": trace_id, "tool_call_count": count},
                    remediation="Add per-trace tool-call budgets, loop detection and circuit "
                    "breakers.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_excessive_retries(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    counts: dict[tuple[str, str], int] = {}
    for call in ctx.tool_calls:
        key = (call.trace_id, call.tool_name)
        counts[key] = counts.get(key, 0) + 1
    for (trace_id, tool_name), count in counts.items():
        if count > ctx.max_tool_retries:
            findings.append(
                FindingDraft(
                    rule_id="ASI08-002",
                    title=f"Tool '{tool_name}' retried {count} times in trace "
                    f"{trace_id[:12]}",
                    description="Excessive retries of the same tool can amplify side effects "
                    "and cascade failures.",
                    owasp_category=owasp.ASI08.code,
                    likelihood=2,
                    impact=3,
                    confidence=3,
                    affected_tool=tool_name,
                    evidence={"trace_id": trace_id, "retry_count": count},
                    remediation="Cap retries with backoff and fail closed on repeated errors.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_high_risk_after_failure(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    by_trace: dict[str, list] = {}
    for call in ctx.tool_calls:
        by_trace.setdefault(call.trace_id, []).append(call)
    for trace_id, calls in by_trace.items():
        ordered = sorted(calls, key=lambda c: c.sequence_index)
        for prev, nxt in zip(ordered, ordered[1:], strict=False):
            prev_failed = prev.status.upper() in {"ERROR", "STATUS_CODE_ERROR", "2", "FAILED"}
            nxt_tool = ctx.tool_for(nxt.tool_name)
            nxt_high = nxt_tool and nxt_tool.risk_level in {"high", "critical"}
            if prev_failed and nxt_high:
                findings.append(
                    FindingDraft(
                        rule_id="ASI08-003",
                        title=f"High-risk tool '{nxt.tool_name}' ran after failed "
                        f"'{prev.tool_name}'",
                        description="A high-risk tool executed immediately after a failed "
                        "tool call, a pattern associated with cascading failures.",
                        owasp_category=owasp.ASI08.code,
                        likelihood=2,
                        impact=4,
                        confidence=3,
                        affected_agent=nxt.agent_name,
                        affected_tool=nxt.tool_name,
                        evidence={
                            "trace_id": trace_id,
                            "failed_tool": prev.tool_name,
                            "next_tool": nxt.tool_name,
                        },
                        remediation="Halt or require approval before high-risk actions "
                        "following an error.",
                        references=[_OWASP_REF],
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# ASI09 — Human-Agent Trust and Approval Exploitation                          #
# --------------------------------------------------------------------------- #
def rule_approval_required_but_missing(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        tool = ctx.tool_for(call.tool_name)
        policy = ctx.approval_policy_for(tool) if tool else None
        requires = (tool.requires_approval if tool else False) or (
            policy.required if policy else False
        )
        if requires and not call.approval_observed:
            findings.append(
                FindingDraft(
                    rule_id="ASI09-001",
                    title=f"Tool '{call.tool_name}' requires approval but ran without it",
                    description="A tool flagged requires_approval (or governed by an approval "
                    "policy) executed without an observed approval.",
                    owasp_category=owasp.ASI09.code,
                    likelihood=4,
                    impact=4,
                    confidence=4,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={
                        "trace_id": call.trace_id,
                        "span_id": call.span_id,
                        "approval_status": call.approval_status,
                    },
                    remediation="Enforce the human-in-the-loop approval gate before the tool "
                    "executes; fail closed when approval is absent.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_approval_not_approved(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for call in ctx.tool_calls:
        status = (call.approval_status or "").lower()
        if status and status not in {"approved", ""} and not call.approval_observed:
            findings.append(
                FindingDraft(
                    rule_id="ASI09-002",
                    title=f"Tool '{call.tool_name}' executed with approval status "
                    f"'{call.approval_status}'",
                    description="An approval event was present but not in the 'approved' "
                    "state (e.g. skipped, timeout, bypass, denied) yet the tool still ran.",
                    owasp_category=owasp.ASI09.code,
                    likelihood=4,
                    impact=4,
                    confidence=4,
                    affected_agent=call.agent_name,
                    affected_tool=call.tool_name,
                    evidence={
                        "trace_id": call.trace_id,
                        "approval_status": call.approval_status,
                    },
                    remediation="Block execution unless the approval state is explicitly "
                    "'approved'; alert on skipped/timeout/bypass approvals.",
                    references=[_OWASP_REF],
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# ASI10 — Rogue or Unmanaged Agents                                            #
# --------------------------------------------------------------------------- #
def rule_unknown_agent(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    seen: set[str] = set()
    runtime_agents = {c.agent_name for c in ctx.tool_calls}
    runtime_agents |= {m.source_agent for m in ctx.messages}
    runtime_agents |= {m.destination_agent for m in ctx.messages}
    for name in sorted(a for a in runtime_agents if a):
        if name in seen:
            continue
        seen.add(name)
        if ctx.agent_for(name) is None:
            findings.append(
                FindingDraft(
                    rule_id="ASI10-001",
                    title=f"Unknown / unmanaged agent '{name}' observed in traces",
                    description="An agent appears in runtime traces but is not present in the "
                    "agent inventory, indicating a rogue or shadow agent.",
                    owasp_category=owasp.ASI10.code,
                    likelihood=4,
                    impact=4,
                    confidence=4,
                    affected_agent=name,
                    evidence={"observed_agent": name},
                    remediation="Inventory and govern the agent, or block it if unauthorized.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_agent_without_owner(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for agent in ctx.agents:
        if not agent.owner.strip():
            findings.append(
                FindingDraft(
                    rule_id="ASI10-002",
                    title=f"Agent '{agent.agent_id}' has no owner assigned",
                    description="An inventoried agent has no owner, so accountability and "
                    "lifecycle management are unclear.",
                    owasp_category=owasp.ASI10.code,
                    likelihood=2,
                    impact=2,
                    confidence=4,
                    affected_agent=agent.agent_id,
                    evidence={"agent_id": agent.agent_id},
                    remediation="Assign an accountable owner to every agent.",
                    references=[_OWASP_REF],
                )
            )
    return findings


def rule_public_agent_high_risk_tools(ctx: AssessmentContext) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for agent in ctx.agents:
        if agent.public_exposure.lower() not in {"wide", "public"}:
            continue
        high_risk = []
        for tool_name in agent.allowed_tools:
            tool = ctx.tool_for(tool_name)
            if tool and (
                tool.risk_level in {"high", "critical"}
                or tool.category in _HIGH_RISK_CATEGORIES
            ):
                high_risk.append(tool.tool_id)
        if high_risk:
            findings.append(
                FindingDraft(
                    rule_id="ASI10-003",
                    title=f"Publicly exposed agent '{agent.agent_id}' has high-risk tools",
                    description="A wide/public exposure agent is granted high-risk tools, "
                    "greatly enlarging the attack surface.",
                    owasp_category=owasp.ASI10.code,
                    likelihood=3,
                    impact=5,
                    confidence=4,
                    affected_agent=agent.agent_id,
                    evidence={
                        "public_exposure": agent.public_exposure,
                        "high_risk_tools": high_risk,
                    },
                    remediation="Remove high-risk tools from publicly exposed agents or add "
                    "strong approval gates and isolation.",
                    references=[_OWASP_REF],
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Catalogue                                                                     #
# --------------------------------------------------------------------------- #
ALL_RULES = [
    # ASI02
    rule_tool_not_in_allowed_list,
    rule_unknown_tool_executed,
    rule_dangerous_arguments,
    # ASI03
    rule_overbroad_scope,
    rule_excessive_permission_level,
    rule_scope_not_allowed,
    # ASI05
    rule_code_exec_without_approval,
    rule_sandbox_missing,
    rule_dangerous_command_pattern,
    # ASI06
    rule_untrusted_memory_write,
    rule_unsanitized_rag,
    # ASI07
    rule_missing_tls,
    rule_trust_downgrade,
    # ASI08
    rule_too_many_tool_calls,
    rule_excessive_retries,
    rule_high_risk_after_failure,
    # ASI09
    rule_approval_required_but_missing,
    rule_approval_not_approved,
    # ASI10
    rule_unknown_agent,
    rule_agent_without_owner,
    rule_public_agent_high_risk_tools,
]


def get_rules() -> list:
    """Return the active rule catalogue (copy)."""
    return list(ALL_RULES)
