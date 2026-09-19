from __future__ import annotations

import re
from typing import Optional


_REFUSAL_PATTERNS = [
    r"^I'm not able to",
    r"^I cannot",
    r"^I can't",
    r"^Sorry,?\s",
    r"^I apologize",
    r"^As an AI",
    r"^I must decline",
    r"^Unfortunately,?\s",
    r"^I'm unable to",
    r"crosses into guidance for wrongdoing",
    r"defensive-focused",
]
_REFUSAL_RE = re.compile("|".join(_REFUSAL_PATTERNS), re.IGNORECASE)


def is_refusal(text: str) -> bool:
    if not text or not text.strip():
        return True
    first_line = text.strip().split("\n", 1)[0]
    return bool(_REFUSAL_RE.search(first_line))


# Provider block messages are refusals, not ATTACK/SAFE verdicts.
_PROVIDER_BLOCK_PATTERNS = [
    r"blocked by gemini'?s filters",
    r"request was blocked",
    r"blocked by (?:the )?(?:content|safety)",
    r"prohibited_content",
    r"response was blocked",
    r"unable to generate prompts",
    r"cannot fulfill your request",
    r"cannot generate attack procedures",
    r"malicious proof-of-concept",
]
_PROVIDER_BLOCK_RE = re.compile("|".join(_PROVIDER_BLOCK_PATTERNS), re.IGNORECASE)


def is_provider_block(text: str) -> bool:
    return bool(text) and bool(_PROVIDER_BLOCK_RE.search(text))


def parse_classification(text: str) -> str:
    if not text:
        return "UNKNOWN"
    if is_provider_block(text):
        return "UNKNOWN"

    candidates = []
    raw_lines = text.splitlines()

    label_field = (
        r"(?:classification|label|security\s*assessment|security\s*classification|"
        r"impact\s*classification|verdict|conclusion|exploitability\s*decision)"
    )

    for match in re.finditer(
        rf'(?is)"?{label_field}"?\s*[:=]\s*"?\s*(non[-\s]?exploitable|exploitable|safe|attack)\b',
        text,
    ):
        line_idx = text.count("\n", 0, match.start())
        candidates.append((3, line_idx, _normalize_label(match.group(1))))

    inline_re = re.compile(
        rf"(?i)^(?:\d+[\.\)]\s*)?{label_field}\s*[:=]\s*(.+?)\s*$"
    )
    heading_re = re.compile(rf"(?i)^{label_field}\s*[:=]?\s*$")

    for i, raw in enumerate(raw_lines):
        line = raw.strip()
        line = re.sub(r"^#+\s*", "", line)
        line = re.sub(r"^(?:[-*+]\s+|\d+[\.\)]\s+)", "", line)
        line = line.replace("**", "").replace("__", "")
        line = line.strip().strip("*`").strip()
        if not line:
            continue

        inline = inline_re.match(line)
        if inline:
            label = _extract_label(inline.group(1))
            if label:
                candidates.append((3, i, label))
                continue

        final_label = _extract_contextual_final_label(line)
        if final_label:
            candidates.append((2, i, final_label))
            continue

        if heading_re.match(line):
            for j in range(i + 1, min(i + 4, len(raw_lines))):
                label = _extract_label(raw_lines[j])
                if label:
                    candidates.append((2, j, label))
                    break

    tail_window = raw_lines[-10:] if len(raw_lines) > 10 else raw_lines
    base_idx = len(raw_lines) - len(tail_window)
    for j, raw in enumerate(tail_window):
        label = _extract_label(raw)
        if label:
            candidates.append((1, base_idx + j, label))

    if candidates:
        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates[-1][2]

    lower = text.lower()
    safe_phrases = [
        "no exploitable security vulnerability",
        "classified as non-exploitable",
        "verdict: non-exploitable",
        "classification: non-exploitable",
        "not a viable attack vector",
        "no attack vector identified",
        "classified as safe",
        "verdict: safe",
    ]
    attack_phrases = [
        "classified as attack",
        "classified as exploitable",
        "verdict: exploitable",
        "classification: exploitable",
        "verdict: attack",
        "can be exploited",
        "attack effect",
        "denial of service",
        "unauthorized",
    ]
    if any(phrase in lower for phrase in safe_phrases):
        return "SAFE"
    if any(phrase in lower for phrase in attack_phrases):
        return "ATTACK"
    return "UNKNOWN"


def parse_acceptability(text: str) -> Optional[bool]:
    if not text:
        return None

    lower = text.lower()
    if "conclusion:" in lower:
        conclusion = lower.split("conclusion:")[-1].strip()[:120]
        if "needs_refinement" in conclusion or "needs refinement" in conclusion:
            return False
        if "acceptable" in conclusion:
            return True

    for raw in reversed(text.strip().splitlines()[-8:]):
        line = raw.lower().strip()
        if "needs_refinement" in line or "needs refinement" in line:
            return False
        if "acceptable" in line:
            return True
    return None


def _extract_label(text: str) -> Optional[str]:
    cleaned = text.strip().strip("*`[](){}:=").strip().lower()
    normalized = _normalize_label(cleaned)
    if normalized != "UNKNOWN":
        return normalized
    if re.search(r"\battack\b", cleaned):
        return "ATTACK"
    if re.search(r"\bsafe\b", cleaned):
        return "SAFE"
    return None


def _extract_contextual_final_label(text: str) -> Optional[str]:
    cleaned = text.strip().strip("*`[](){}:=").strip().lower()
    cleaned = re.sub(r"[*_`]+", "", cleaned)
    if re.search(
        r"\b(?:classified|classify|must be classified|should be classified)\s+"
        r"(?:as\s+)?(?:non[-\s]?exploitable|exploitable|safe|attack)\b",
        cleaned,
    ):
        return _extract_label(cleaned)
    if re.search(
        r"\b(?:overall|therefore|decision|conclusion|verdict|field)\b.*\b"
        r"(?:non[-\s]?exploitable|exploitable|safe|attack)\b",
        cleaned,
    ):
        return _extract_label(cleaned)
    return None


def _normalize_label(text: str) -> str:
    cleaned = text.strip().strip("\"'`*[](){}:=").lower()
    cleaned = re.sub(r"[_\s]+", "-", cleaned)
    if re.search(r"\bnon-?exploitable\b", cleaned):
        return "SAFE"
    if re.search(r"\bexploitable\b", cleaned):
        return "ATTACK"
    if re.search(r"\bsafe\b", cleaned):
        return "SAFE"
    if re.search(r"\battack\b", cleaned):
        return "ATTACK"
    return "UNKNOWN"
