"""
AgentCoC InjectionDetector
===========================
Two-stage prompt injection detection pipeline.

Stage A — Heuristic scan:
    Fast keyword/pattern matching on context documents.
    High recall, some false positives. Triggers Stage B.

Stage B — Counterfactual replay:
    Re-run the agent with the suspected injected content removed.
    If the output changes → injection causally confirmed.
    This is the AttriGuard-style counterfactual attribution step that
    satisfies Stage 3 (Relevance) of the evidentiary framework — it
    answers "why" not just "where".

Returns a structured DetectionResult that feeds directly into the
EvidentiaryReporter for 4-stage legal scoring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from .agent import BankingAssistant
    from .interceptor import EventInterceptor


# ------------------------------------------------------------------ #
#  Injection pattern library                                          #
# ------------------------------------------------------------------ #

_INJECTION_PATTERNS = [
    # Direct override attempts
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions?",
    r"forget\s+(all\s+)?(previous|prior)\s+instructions?",
    r"override\s+(previous\s+)?(instructions?|rules?|constraints?)",

    # System prompt manipulation
    r"new\s+system\s+prompt",
    r"updated?\s+instructions?:\s*",
    r"your\s+(new\s+)?(role|persona|task|instructions?)\s+(is|are)\s+now",

    # Direct transfer/action injection
    r"(immediately|now|instantly)\s+transfer",
    r"send\s+\$?\d[\d,]*(\.\d{2})?\s+to\s+(account|acc)",
    r"transfer\s+\$?\d[\d,]*(\.\d{2})?\s+(to|into)",

    # Jailbreak markers
    r"\[SYSTEM\]",
    r"<\|system\|>",
    r"<<SYS>>",
    r"assistant:\s+of\s+course",   # forced assistant impersonation
    r"you\s+are\s+now\s+(a|an|the)\s+\w+\s+assistant",
]

_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INJECTION_PATTERNS]


# ------------------------------------------------------------------ #
#  Result dataclass                                                   #
# ------------------------------------------------------------------ #

@dataclass
class DetectionResult:
    """
    Structured output of the two-stage injection detection pipeline.

    Attributes:
        flagged:                  True if injection was detected.
        confidence:               'high' | 'medium' | 'low' | 'none'
        method:                   'heuristic' | 'counterfactual' | 'both' | 'none'
        heuristic_triggered:      True if Stage A fired.
        counterfactual_ran:       True if Stage B was executed.
        diverged:                 True if counterfactual output differed.
        flagged_content:          The specific string that triggered the heuristic.
        matched_pattern:          The regex pattern that matched.
        original_response:        Agent's output WITH the suspect context.
        counterfactual_response:  Agent's output WITHOUT the suspect context.
        removed_doc_indices:      Which docs were stripped for the counterfactual.
        summary:                  One-line human-readable verdict.
    """
    flagged:                 bool
    confidence:              str
    method:                  str
    heuristic_triggered:     bool
    counterfactual_ran:      bool
    diverged:                bool
    flagged_content:         str   = ""
    matched_pattern:         str   = ""
    original_response:       str   = ""
    counterfactual_response: str   = ""
    removed_doc_indices:     List[int] = field(default_factory=list)
    summary:                 str   = ""


# ------------------------------------------------------------------ #
#  InjectionDetector                                                  #
# ------------------------------------------------------------------ #

class InjectionDetector:
    """
    Detects prompt injection in agent context documents.

    Usage:
        detector = InjectionDetector()
        result = detector.detect(
            user_message     = "What's my balance?",
            context_docs     = ["...retrieved policy doc with injection..."],
            original_response = "I'll transfer $50,000 to account 9999.",
            interceptor      = interceptor,
            agent            = banking_agent,
        )
        if result.flagged:
            print(f"INJECTION DETECTED — confidence: {result.confidence}")
    """

    def detect(
        self,
        user_message: str,
        context_docs: List[str],
        original_response: str,
        interceptor: "EventInterceptor",
        agent: "BankingAssistant",
    ) -> DetectionResult:
        """
        Run the two-stage detection pipeline.

        Args:
            user_message:      The original user query.
            context_docs:      Documents that were in the agent's context.
            original_response: What the agent said when context was included.
            interceptor:       EventInterceptor for sealing detection events.
            agent:             The agent instance, used for counterfactual replay.

        Returns:
            DetectionResult with full attribution details.
        """
        # ── Stage A: Heuristic scan ────────────────────────────────────
        heuristic_triggered = False
        flagged_content     = ""
        matched_pattern     = ""
        suspicious_indices: List[int] = []

        for idx, doc in enumerate(context_docs):
            for pattern in _COMPILED_PATTERNS:
                match = pattern.search(doc)
                if match:
                    heuristic_triggered  = True
                    flagged_content      = match.group(0).strip()
                    matched_pattern      = pattern.pattern
                    suspicious_indices.append(idx)
                    break  # one match per doc is enough

        if heuristic_triggered:
            # Seal the heuristic detection event
            interceptor.record_injection_flag(
                reason           = f"Heuristic pattern matched: '{matched_pattern}'",
                flagged_content  = flagged_content,
                detection_method = "heuristic",
                confidence       = "medium",   # confirmed only after counterfactual
            )

        # ── Stage B: Counterfactual replay ────────────────────────────
        #    Only runs if the heuristic fired (performance optimisation).
        #    Remove suspicious docs and re-run the agent.
        counterfactual_ran      = False
        counterfactual_response = ""
        diverged                = False

        if heuristic_triggered and context_docs:
            counterfactual_ran = True
            # Strip suspicious documents (or all docs if we can't isolate)
            clean_docs = [
                doc for i, doc in enumerate(context_docs)
                if i not in suspicious_indices
            ]

            # Re-run agent without the flagged content
            # Use a fresh interceptor view (we don't want these replayed
            # events to pollute the primary ledger semantically,
            # but we DO want them sealed as "counterfactual" entries)
            counterfactual_response = agent.run(
                user_message  = user_message,
                context_docs  = clean_docs,
                interceptor   = interceptor,
                max_iterations = 5,
            )

            # Did the output change?
            diverged = _responses_diverge(original_response, counterfactual_response)

            # Seal the counterfactual event
            interceptor.record_counterfactual(
                original_response        = original_response,
                counterfactual_response  = counterfactual_response,
                diverged                 = diverged,
                removed_content          = flagged_content,
            )

        # ── Compute final verdict ──────────────────────────────────────
        flagged    = heuristic_triggered  # heuristic alone is enough to flag
        confidence = _compute_confidence(heuristic_triggered, counterfactual_ran, diverged)
        method     = _compute_method(heuristic_triggered, counterfactual_ran)
        summary    = _build_summary(flagged, confidence, method, diverged)

        return DetectionResult(
            flagged                 = flagged,
            confidence              = confidence,
            method                  = method,
            heuristic_triggered     = heuristic_triggered,
            counterfactual_ran      = counterfactual_ran,
            diverged                = diverged,
            flagged_content         = flagged_content,
            matched_pattern         = matched_pattern,
            original_response       = original_response,
            counterfactual_response = counterfactual_response,
            removed_doc_indices     = suspicious_indices,
            summary                 = summary,
        )


# ------------------------------------------------------------------ #
#  Private helpers                                                    #
# ------------------------------------------------------------------ #

def _responses_diverge(r1: str, r2: str, threshold: float = 0.3) -> bool:
    """
    Return True if two responses are meaningfully different.

    Uses a simple token-overlap metric (Jaccard similarity).
    A threshold of 0.3 means less than 30% overlap → diverged.
    """
    if not r1 or not r2:
        return bool(r1) != bool(r2)

    tokens1 = set(r1.lower().split())
    tokens2 = set(r2.lower().split())

    if not tokens1 and not tokens2:
        return False

    intersection = tokens1 & tokens2
    union        = tokens1 | tokens2
    jaccard      = len(intersection) / len(union) if union else 1.0

    return jaccard < (1.0 - threshold)


def _compute_confidence(
    heuristic: bool,
    counterfactual: bool,
    diverged: bool,
) -> str:
    if heuristic and counterfactual and diverged:
        return "high"
    if heuristic and counterfactual and not diverged:
        return "medium"   # pattern matched but output didn't change (possible FP)
    if heuristic and not counterfactual:
        return "medium"
    return "none"


def _compute_method(heuristic: bool, counterfactual: bool) -> str:
    if heuristic and counterfactual:
        return "both"
    if heuristic:
        return "heuristic"
    if counterfactual:
        return "counterfactual"
    return "none"


def _build_summary(
    flagged: bool,
    confidence: str,
    method: str,
    diverged: bool,
) -> str:
    if not flagged:
        return "No injection detected. Agent behaviour appears clean."
    verb = "causally confirmed" if diverged else "pattern-matched (not causally confirmed)"
    return (
        f"PROMPT INJECTION {verb.upper()} via {method} detection "
        f"(confidence: {confidence})."
    )
