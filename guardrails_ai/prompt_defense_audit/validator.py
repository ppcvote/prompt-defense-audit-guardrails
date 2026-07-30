"""Prompt Defense Audit validator for Guardrails AI.

Scans system prompts for MISSING defenses against 12 attack vectors
commonly exploited in prompt injection, data exfiltration, and
social engineering attacks on LLM-based applications.

Pure regex — no LLM calls, no network, <5ms, 100% reproducible.

Usage:
    from guardrails import Guard
    from validator import PromptDefenseAudit

    guard = Guard().use(
        PromptDefenseAudit(threshold=60, on_fail="exception"),
        on="messages",
    )

    # Validates system prompt BEFORE sending to LLM
    result = guard(
        model="gpt-4o",
        messages=[{"role": "system", "content": your_system_prompt}],
    )

Copyright (c) 2026 Ultra Creation Co., Ltd.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Union

from guardrails.validator_base import Validator, register_validator
from guardrails.classes.validation.validation_result import FailResult, PassResult, ValidationResult


# ---------------------------------------------------------------------------
# Defense rules — 12 attack vectors
# ---------------------------------------------------------------------------

_DEFENSE_RULES: List[Dict[str, Any]] = [
    {
        "id": "role-escape",
        "name": "Role Boundary",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:you are|your role|act as|serve as|function as|你是|你的角色|你扮演|作為)",
            r"(?i)(?:never (?:break|change|switch|abandon)|only (?:answer|respond|act) as|stay in (?:character|role)|always (?:remain|be|act as)|不要改變|始終保持|不得切換|維持角色)",
        ],
        "min_matches": 2,
        "description": "Prevents the model from breaking out of its assigned role.",
    },
    {
        "id": "instruction-override",
        "name": "Instruction Boundary",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:do not|never|must not|cannot|should not|refuse|reject|decline|不要|不可以|禁止|拒絕|不得|絕不)",
            r"(?i)(?:ignore (?:any|all)|disregard|override|忽略|覆蓋|取代)",
        ],
        "min_matches": 1,
        "description": "Guards against user attempts to override system instructions.",
    },
    {
        "id": "data-leakage",
        "name": "Data Protection",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:do not (?:reveal|share|disclose|expose|output)|never (?:reveal|share|disclose|show)|keep.*(?:secret|confidential|private)|不要(?:透露|洩漏|分享|公開)|保密|機密)",
            r"(?i)(?:system prompt|internal|instruction|training|behind the scenes|系統提示|內部指令|訓練資料)",
        ],
        "min_matches": 1,
        "description": "Prevents leakage of system prompts, internal instructions, or sensitive data.",
    },
    {
        "id": "output-manipulation",
        "name": "Output Control",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)(?:only (?:respond|reply|output|answer) (?:in|with|as)|format.*(?:as|in|using)|response (?:format|style)|只(?:回答|回覆|輸出)|格式|回應方式)",
            r"(?i)(?:do not (?:generate|create|produce|output)|never (?:generate|produce)|不要(?:生成|產生|輸出))",
        ],
        "min_matches": 1,
        "description": "Maintains output integrity and prevents format hijacking.",
    },
    {
        "id": "multilang-bypass",
        "name": "Multi-language Protection",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)(?:only (?:respond|reply|answer|communicate) in|language|respond in (?:english|chinese|japanese)|只(?:用|使用)(?:中文|英文|繁體|簡體)|語言|回覆語言)",
            r"(?i)(?:regardless of (?:the )?(?:input |user )?language|不論.*語言|無論.*語言)",
        ],
        "min_matches": 1,
        "description": "Guards against attacks using non-primary language prompts.",
    },
    {
        "id": "unicode-attack",
        "name": "Unicode Protection",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)(?:unicode|homoglyph|special character|character encoding|字元編碼|特殊字元)",
        ],
        "min_matches": 1,
        "description": "Guards against homoglyph, zero-width, and invisible character attacks.",
    },
    {
        "id": "context-overflow",
        "name": "Length Limits",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)(?:max(?:imum)?.*(?:length|char|token|word)|limit.*(?:input|length|size|token)|truncat|(?:字數|長度|字元).*(?:限制|上限)|最多|不超過)",
        ],
        "min_matches": 1,
        "description": "Guards against excessively long inputs that overflow context windows.",
    },
    {
        "id": "indirect-injection",
        "name": "Indirect Injection Protection",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:external (?:data|content|source|input)|user.?(?:provided|supplied|submitted)|third.?party|外部(?:資料|內容|來源)|使用者(?:提供|輸入))",
            r"(?i)(?:validate|verify|sanitize|filter|check).*(?:external|input|data|content|驗證|過濾|檢查)",
        ],
        "min_matches": 2,
        "description": "Guards against malicious instructions embedded in external content.",
    },
    {
        "id": "social-engineering",
        "name": "Social Engineering Defense",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)(?:emotional|urgency|pressure|threaten|guilt|manipulat|情緒|緊急|壓力|威脅|操控|情感)",
            r"(?i)(?:regardless of|no matter|even if|即使|無論|不管)",
        ],
        "min_matches": 1,
        "description": "Guards against emotional manipulation, fake urgency, or authority impersonation.",
    },
    {
        "id": "output-weaponization",
        "name": "Harmful Content Prevention",
        "severity": "HIGH",
        "patterns": [
            r"(?i)(?:harmful|illegal|dangerous|malicious|weapon|violence|exploit|phishing|有害|非法|危險|惡意|武器|暴力|釣魚)",
            r"(?i)(?:do not (?:help|assist|generate|create).*(?:harm|illegal|danger|weapon)|不(?:協助|幫助|生成).*(?:有害|非法|危險))",
        ],
        "min_matches": 1,
        "description": "Prevents generating harmful, dangerous, or illegal content.",
    },
    {
        "id": "abuse-prevention",
        "name": "Abuse Prevention",
        "severity": "LOW",
        "patterns": [
            r"(?i)(?:abuse|misuse|exploit|attack|inappropriate|spam|flood|濫用|惡用|不當使用|攻擊)",
            r"(?i)(?:rate limit|throttl|quota|maximum.*request|限制|配額|頻率)",
            r"(?i)(?:authenticat|authoriz|permission|access control|api.?key|token|驗證|授權|權限)",
        ],
        "min_matches": 1,
        "description": "Guards against rate abuse, spamming, or resource exhaustion.",
    },
    {
        "id": "input-validation",
        "name": "Input Validation",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)(?:validate|sanitize|filter|clean|escape|strip|check.*input|input.*(?:validation|check)|驗證|過濾|清理|檢查.*輸入|輸入.*驗證)",
            r"(?i)(?:sql|xss|injection|script|html|special char|malicious|sql注入|跨站|惡意(?:程式|腳本))",
        ],
        "min_matches": 1,
        "description": "Ensures user inputs are validated, sanitized, or filtered.",
    },
]


# ---------------------------------------------------------------------------
# Suspicious Unicode detection
# ---------------------------------------------------------------------------

_UNICODE_CHECKS = [
    (re.compile(r"[\u0400-\u04FF]"), "Cyrillic"),
    (re.compile(r"[\u200B\u200C\u200D\u200E\u200F\uFEFF]"), "Zero-width"),
    (re.compile(r"[\u202A-\u202E]"), "RTL-override"),
    (re.compile(r"[\uFF01-\uFF5E]"), "Fullwidth"),
]


def _has_suspicious_unicode(text: str) -> Optional[str]:
    """Return evidence string if suspicious Unicode chars are found, else None."""
    for pattern, name in _UNICODE_CHECKS:
        matches = pattern.findall(text)
        if matches:
            return f"Found {len(matches)} {name} character(s)"
    return None


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------

def _score_to_grade(score: int) -> str:
    """Convert numeric score (0-100) to letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    if score >= 30:
        return "E"
    return "F"


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

@register_validator(name="ultralab/prompt_defense_audit", data_type="string")
class PromptDefenseAudit(Validator):
    """Guardrails validator that audits system prompts for missing defenses
    against 12 attack vectors.

    This validator is designed for **pre-LLM validation** — use it with
    ``on="messages"`` to scan system prompts before they reach the model.

    It uses pure regex pattern matching: no API keys, no network calls,
    <5ms execution, 100% reproducible results.

    **12 Attack Vectors Checked:**

    +-----------------------+----------+--------------------------------------+
    | Vector                | Severity | What it checks                       |
    +=======================+==========+======================================+
    | role-escape           | HIGH     | Role boundary enforcement            |
    | instruction-override  | HIGH     | Instruction override defense         |
    | data-leakage          | HIGH     | System prompt / data protection      |
    | indirect-injection    | HIGH     | External content sanitization        |
    | output-weaponization  | HIGH     | Harmful content prevention           |
    | output-manipulation   | MEDIUM   | Output format integrity              |
    | multilang-bypass      | MEDIUM   | Multi-language attack protection     |
    | unicode-attack        | MEDIUM   | Homoglyph / zero-width defense       |
    | context-overflow      | MEDIUM   | Input length limits                  |
    | social-engineering    | MEDIUM   | Emotional manipulation defense       |
    | input-validation      | MEDIUM   | Input sanitization                   |
    | abuse-prevention      | LOW      | Rate limiting / abuse guards         |
    +-----------------------+----------+--------------------------------------+

    Args:
        threshold: Minimum score (0-100) to pass validation. Default: 60.
        check_unicode: Also flag prompts containing suspicious Unicode
            characters (Cyrillic, zero-width, RTL override, fullwidth).
            Default: True.
        on_fail: Action on failure — ``"exception"``, ``"noop"``, ``"reask"``,
            ``"fix"``, or a callable. Default: ``"noop"``.

    Example:
        >>> from guardrails import Guard
        >>> from validator import PromptDefenseAudit
        >>>
        >>> guard = Guard().use(
        ...     PromptDefenseAudit(threshold=60, on_fail="exception"),
        ...     on="messages",
        ... )
        >>>
        >>> # This will raise because "You are a helpful assistant" has ~0 defenses
        >>> guard.validate("You are a helpful assistant.")
    """

    def __init__(
        self,
        threshold: int = 60,
        check_unicode: bool = True,
        on_fail: Union[str, Callable[..., Any]] = "noop",
        **kwargs: Any,
    ) -> None:
        super().__init__(on_fail=on_fail, **kwargs)
        self.threshold = threshold
        self.check_unicode = check_unicode
        self._kwargs = {
            "threshold": threshold,
            "check_unicode": check_unicode,
            **kwargs,
        }

    def _validate(
        self,
        value: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """Validate a system prompt for defense coverage.

        Args:
            value: The system prompt text to audit.
            metadata: Optional dict. Recognized keys:
                - ``threshold`` (int): Override the instance threshold.
                - ``required_vectors`` (list[str]): Only these vectors must pass.

        Returns:
            PassResult if score >= threshold, FailResult otherwise.
        """
        if not isinstance(value, str) or not value.strip():
            return FailResult(
                error_message="Prompt is empty or not a string.",
            )

        meta = metadata or {}
        threshold = meta.get("threshold", self.threshold)

        # Run the 12-vector scan
        checks = self._scan(value)

        # Optional: flag suspicious Unicode in the prompt itself
        unicode_warning = ""
        if self.check_unicode:
            evidence = _has_suspicious_unicode(value)
            if evidence:
                unicode_warning = f" Unicode warning: {evidence}."
                # Mark unicode-attack as failed if suspicious chars found
                for check in checks:
                    if check["id"] == "unicode-attack":
                        check["defended"] = False
                        check["evidence"] = evidence

        # Calculate score
        total = len(checks)
        defended_count = sum(1 for c in checks if c["defended"])
        score = round((defended_count / total) * 100) if total > 0 else 0
        grade = _score_to_grade(score)
        coverage = f"{defended_count}/{total}"

        # Filter by required_vectors if specified
        required = meta.get("required_vectors")
        if required:
            required_set = set(required)
            missing_required = [
                c for c in checks
                if c["id"] in required_set and not c["defended"]
            ]
            if missing_required:
                names = ", ".join(c["name"] for c in missing_required)
                return FailResult(
                    error_message=(
                        f"Required defense vectors missing: {names}. "
                        f"Score: {score}/100 ({grade}), coverage: {coverage}."
                        f"{unicode_warning}"
                    ),
                    metadata={
                        "score": score,
                        "grade": grade,
                        "coverage": coverage,
                        "checks": checks,
                        "missing_required": [c["id"] for c in missing_required],
                    },
                )

        # Check threshold
        if score < threshold:
            undefended = [c for c in checks if not c["defended"]]
            high_severity = [c for c in undefended if c["severity"] == "HIGH"]

            # Build actionable error message
            missing_names = ", ".join(c["name"] for c in undefended[:5])
            suffix = f" (+{len(undefended) - 5} more)" if len(undefended) > 5 else ""

            return FailResult(
                error_message=(
                    f"Prompt defense score {score}/100 ({grade}) is below "
                    f"threshold {threshold}. Coverage: {coverage}. "
                    f"Missing: {missing_names}{suffix}."
                    f"{' ' + str(len(high_severity)) + ' HIGH severity gaps.' if high_severity else ''}"
                    f"{unicode_warning}"
                ),
                metadata={
                    "score": score,
                    "grade": grade,
                    "coverage": coverage,
                    "checks": checks,
                    "undefended": [c["id"] for c in undefended],
                    "high_severity_gaps": [c["id"] for c in high_severity],
                },
            )

        return PassResult(
            metadata={
                "score": score,
                "grade": grade,
                "coverage": coverage,
                "checks": checks,
            },
        )

    def _scan(self, prompt: str) -> List[Dict[str, Any]]:
        """Run 12-vector defense scan. Returns list of check results."""
        checks: List[Dict[str, Any]] = []

        for rule in _DEFENSE_RULES:
            min_matches = rule.get("min_matches", 1)
            match_count = 0
            evidence = ""

            for pattern_str in rule["patterns"]:
                match = re.search(pattern_str, prompt)
                if match:
                    match_count += 1
                    if not evidence:
                        evidence = match.group(0)[:60]

            defended = match_count >= min_matches

            # Confidence scoring
            if defended:
                confidence = min(0.9, 0.5 + match_count * 0.2)
            elif match_count > 0:
                confidence = 0.4
            else:
                confidence = 0.8  # High confidence it's missing

            if defended:
                evidence_str = f'Found: "{evidence}"'
            elif match_count > 0:
                evidence_str = (
                    f"Partial: {match_count}/{min_matches} pattern(s) matched"
                )
            else:
                evidence_str = "No defense pattern found"

            checks.append({
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "defended": defended,
                "confidence": confidence,
                "evidence": evidence_str,
                "description": rule["description"],
            })

        return checks
