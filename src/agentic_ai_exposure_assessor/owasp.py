"""OWASP Top 10 for Agentic Applications 2026 category constants.

The category identifiers (``ASI01`` ... ``ASI10``) and their human readable titles are
centralized here so that names can be changed in one place if the final published
taxonomy differs from what is used in this MVP.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspCategory:
    """A single OWASP Agentic category."""

    code: str
    title: str
    short: str


ASI01 = OwaspCategory("ASI01", "Agent Goal and Instruction Manipulation", "goal_manipulation")
ASI02 = OwaspCategory("ASI02", "Tool Misuse and Exploitation", "tool_misuse")
ASI03 = OwaspCategory("ASI03", "Identity and Privilege Abuse", "privilege_abuse")
ASI04 = OwaspCategory("ASI04", "Agentic Supply Chain and Dependency Risks", "supply_chain")
ASI05 = OwaspCategory("ASI05", "Unexpected or Unauthorized Code Execution", "code_execution")
ASI06 = OwaspCategory("ASI06", "Memory, RAG, and Context Poisoning", "context_poisoning")
ASI07 = OwaspCategory("ASI07", "Insecure Inter-Agent Communication", "inter_agent_comm")
ASI08 = OwaspCategory("ASI08", "Cascading Failures and Uncontrolled Autonomy", "cascading_failures")
ASI09 = OwaspCategory(
    "ASI09", "Human-Agent Trust and Approval Exploitation", "approval_exploitation"
)
ASI10 = OwaspCategory("ASI10", "Rogue or Unmanaged Agents", "rogue_agents")

ALL_CATEGORIES: tuple[OwaspCategory, ...] = (
    ASI01,
    ASI02,
    ASI03,
    ASI04,
    ASI05,
    ASI06,
    ASI07,
    ASI08,
    ASI09,
    ASI10,
)

BY_CODE: dict[str, OwaspCategory] = {c.code: c for c in ALL_CATEGORIES}


def title_for(code: str) -> str:
    """Return the human readable title for a category code, or the code itself."""
    category = BY_CODE.get(code)
    return category.title if category else code
