"""Repo-local compatibility shim — not shipped in the PyPI wheel.

The canonical import is ``prompt_defense_audit_guardrails``. This shim keeps
``from validator import PromptDefenseAudit`` working for existing clones.
"""

from prompt_defense_audit_guardrails import PromptDefenseAudit

__all__ = ["PromptDefenseAudit"]
