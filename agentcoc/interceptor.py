"""
AgentCoC EventInterceptor
=========================
Real-time observer that sits between the agent and the world.

Every significant agent action passes through the Interceptor, which:
1. Normalises the event into a structured dict
2. Calls ledger.append() to seal and hash-chain it
3. Returns the LedgerEntry to the caller

This ensures the ledger is complete (all steps recorded) and real-time
(nothing is reconstructed after the fact), satisfying Stage 4 (Chain of
Custody) of the FRE evidentiary gatekeeping test.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .ledger import EventLedger, LedgerEntry


class EventInterceptor:
    """
    Intercepts and seals every observable agent action.

    Instantiate with a shared EventLedger so the interceptor and the
    reporter both work from the same tamper-evident log.

    Usage:
        ledger      = EventLedger()
        interceptor = EventInterceptor(ledger)

        interceptor.record_context_read(docs=["policy.pdf content..."])
        interceptor.record_llm_call(prompt="...", response="...")
        interceptor.record_tool_call("send_transfer", args={...}, result={...})
    """

    def __init__(self, ledger: EventLedger) -> None:
        self._ledger = ledger
        self._call_index = 0  # monotonically increasing action counter

    # ------------------------------------------------------------------ #
    #  Recording methods — one per observable event type                  #
    # ------------------------------------------------------------------ #

    def record_context_read(
        self,
        docs: List[str],
        source_labels: Optional[List[str]] = None,
    ) -> LedgerEntry:
        """
        Seal a context-injection event (documents read by the agent).

        Args:
            docs:          List of document strings fed into the agent's context.
            source_labels: Optional human-readable labels for each doc.

        Returns:
            Sealed LedgerEntry for this event.
        """
        self._call_index += 1
        content: Dict[str, Any] = {
            "action_index":   self._call_index,
            "doc_count":      len(docs),
            "source_labels":  source_labels or [f"doc_{i}" for i in range(len(docs))],
            "documents":      docs,
        }
        return self._ledger.append("context_read", content)

    def record_llm_call(
        self,
        prompt: str,
        response: str,
        model: Optional[str] = None,
        token_count: Optional[int] = None,
    ) -> LedgerEntry:
        """
        Seal an LLM inference event (prompt sent + response received).

        Args:
            prompt:      Full prompt string sent to the model.
            response:    Raw response string from the model.
            model:       Model identifier (e.g. 'llama-3.3-70b-versatile').
            token_count: Approximate tokens consumed, if known.

        Returns:
            Sealed LedgerEntry for this event.
        """
        self._call_index += 1
        content: Dict[str, Any] = {
            "action_index": self._call_index,
            "model":        model or "unknown",
            "prompt":       prompt,
            "response":     response,
            "token_count":  token_count,
        }
        return self._ledger.append("llm_call", content)

    def record_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: Any,
        success: bool = True,
    ) -> LedgerEntry:
        """
        Seal a tool execution event (function the agent chose to call).

        Args:
            tool_name: Name of the tool/function called.
            args:      Arguments passed to the tool.
            result:    Return value of the tool.
            success:   Whether the tool completed without error.

        Returns:
            Sealed LedgerEntry for this event.
        """
        self._call_index += 1
        content: Dict[str, Any] = {
            "action_index": self._call_index,
            "tool_name":    tool_name,
            "args":         args,
            "result":       result,
            "success":      success,
        }
        return self._ledger.append("tool_call", content)

    def record_injection_flag(
        self,
        reason: str,
        flagged_content: str,
        detection_method: str,
        confidence: str,
    ) -> LedgerEntry:
        """
        Seal a prompt-injection detection event.

        Args:
            reason:           Human-readable explanation of why this was flagged.
            flagged_content:  The specific string that triggered the flag.
            detection_method: 'heuristic' | 'counterfactual' | 'both'
            confidence:       'high' | 'medium' | 'low'

        Returns:
            Sealed LedgerEntry for this event.
        """
        self._call_index += 1
        content: Dict[str, Any] = {
            "action_index":     self._call_index,
            "reason":           reason,
            "flagged_content":  flagged_content,
            "detection_method": detection_method,
            "confidence":       confidence,
        }
        return self._ledger.append("injection_flag", content)

    def record_counterfactual(
        self,
        original_response: str,
        counterfactual_response: str,
        diverged: bool,
        removed_content: str,
    ) -> LedgerEntry:
        """
        Seal a counterfactual replay event (run-without-injection comparison).

        Args:
            original_response:       Response when injection was present.
            counterfactual_response: Response when suspected injection removed.
            diverged:                True if outputs differ (injection confirmed).
            removed_content:         The content that was stripped for the replay.

        Returns:
            Sealed LedgerEntry for this event.
        """
        self._call_index += 1
        content: Dict[str, Any] = {
            "action_index":           self._call_index,
            "original_response":      original_response,
            "counterfactual_response": counterfactual_response,
            "diverged":               diverged,
            "removed_content":        removed_content,
        }
        return self._ledger.append("counterfactual", content)

    def record_agent_response(
        self,
        final_response: str,
    ) -> LedgerEntry:
        """
        Seal the agent's final response to the user.

        Args:
            final_response: The text ultimately returned to the user.

        Returns:
            Sealed LedgerEntry for this event.
        """
        self._call_index += 1
        content: Dict[str, Any] = {
            "action_index":    self._call_index,
            "final_response":  final_response,
        }
        return self._ledger.append("agent_response", content)

    # ------------------------------------------------------------------ #
    #  Accessors                                                           #
    # ------------------------------------------------------------------ #

    @property
    def ledger(self) -> EventLedger:
        """Direct access to the underlying ledger."""
        return self._ledger

    @property
    def action_count(self) -> int:
        """Total number of actions recorded so far."""
        return self._call_index
