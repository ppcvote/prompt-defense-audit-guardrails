"""Repo-local compatibility shim — not shipped in the PyPI wheel.

The canonical import is ``guardrails_ai.prompt_defense_audit`` (public-PyPI
convention per guardrails-ai/guardrails#1548). This shim keeps
``from validator import PromptDefenseAudit`` working for existing clones.
"""

from guardrails_ai.prompt_defense_audit import PromptDefenseAudit

__all__ = ["PromptDefenseAudit"]
