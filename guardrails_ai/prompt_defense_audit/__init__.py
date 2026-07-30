"""Prompt Defense Audit — Guardrails validator (public-PyPI packaging).

Installed as ``guardrails-ai-prompt-defense-audit`` per the post-Hub-CLI
convention (guardrails-ai/guardrails#1548): import as
``guardrails_ai.prompt_defense_audit``, or via the ``guardrails.hub``
back-compat shim.

Audits system prompts for missing defenses against 12 attack vectors.
Pure regex, zero external deps, <5ms execution.
"""

from .validator import PromptDefenseAudit

__all__ = ["PromptDefenseAudit"]
