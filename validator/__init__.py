"""Prompt Defense Audit — Guardrails Hub Validator.

Audits system prompts for missing defenses against 12 attack vectors.
Pure regex, zero external deps, <5ms execution.
"""

from .validator import PromptDefenseAudit

__all__ = ["PromptDefenseAudit"]
