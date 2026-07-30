"""Prompt Defense Audit — a Guardrails validator by Ultra Lab.

Install from public PyPI (the Guardrails Hub CLI and private registry are
deprecated upstream, guardrails-ai/guardrails#1548)::

    pip install prompt-defense-audit-guardrails

Namespaced under its own name rather than ``guardrails_ai.*`` so ownership
is unambiguous: this is a third-party validator, not an official Guardrails
AI package.

Audits system prompts for missing defenses against 12 attack vectors.
Pure regex, zero runtime deps beyond ``guardrails-ai``, <5ms execution.
"""

from .validator import PromptDefenseAudit

__all__ = ["PromptDefenseAudit"]
