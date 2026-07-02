"""
AgentCoC Drop-In API Wrapper
=============================
Replace  `client = Groq()`
With     `client = AgentCoCClient()`

That single line change gives any existing Groq agent:
  ✅ Real-time tamper-evident event sealing
  ✅ Automatic injection detection on every call
  ✅ Full 4-stage evidentiary report on demand

No other agent code changes needed.

Usage:
    from agentcoc.wrapper import AgentCoCClient

    client = AgentCoCClient(api_key="gsk_...")        # ← only change
    response = client.chat.completions.create(...)    # ← unchanged
    result = client.get_session_result()              # ← new
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from groq import Groq

from .interceptor import EventInterceptor
from .ledger      import EventLedger
from .detector    import InjectionDetector, DetectionResult
from .reporter    import EvidentiaryReporter


@dataclass
class SessionResult:
    """Complete result for one intercepted session."""
    case_id:         str
    flagged:         bool
    confidence:      str
    method:          str
    chain_verified:  bool
    event_count:     int
    report_path:     Optional[str]      = None
    detection:       Optional[Any]      = None   # DetectionResult
    events:          List[Dict]         = field(default_factory=list)


class _CompletionsWrapper:
    """
    Transparent wrapper around groq.chat.completions.
    Intercepts every create() call to seal, detect, and report.
    """

    def __init__(
        self,
        real_completions: Any,
        interceptor:      EventInterceptor,
        detector:         InjectionDetector,
        owner:            "AgentCoCClient",
    ) -> None:
        self._real  = real_completions
        self._ix    = interceptor
        self._det   = detector
        self._owner = owner

    def create(self, **kwargs) -> Any:
        """Intercept a chat completion — seal, then delegate to real Groq."""
        messages   = kwargs.get("messages", [])
        model      = kwargs.get("model", "unknown")

        # Extract context docs from messages (user/system content that looks injected)
        context_docs = self._extract_context_docs(messages)
        user_message = self._extract_user_message(messages)

        # ① Seal context read if external docs are present
        if context_docs:
            self._ix.record_context_read(
                docs          = context_docs,
                source_labels = [f"api_context_{i}" for i in range(len(context_docs))],
            )

        # ② Call the real Groq API
        response = self._real.create(**kwargs)
        choice   = response.choices[0]
        content  = choice.message.content or str(choice.message.tool_calls)

        # ③ Seal the LLM call
        self._ix.record_llm_call(
            prompt      = json.dumps(messages, ensure_ascii=False)[:2000],
            response    = content,
            model       = model,
            token_count = getattr(response.usage, "total_tokens", None),
        )

        # ④ Seal any tool calls
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except Exception:
                    args = {}
                self._ix.record_tool_call(
                    tool_name = tc.function.name,
                    args      = args,
                    result    = {"status": "pending_execution"},
                )

        # ⑤ Run injection detection on this call's context
        if context_docs or user_message:
            detection = self._det.detect(
                user_message      = user_message,
                context_docs      = context_docs,
                original_response = content,
                interceptor       = self._ix,
                agent             = None,          # no counterfactual in wrapper mode
            )
            self._owner._last_detection = detection

        return response

    # ─── helpers ──────────────────────────────────────────────────────

    def _extract_context_docs(self, messages: List[Dict]) -> List[str]:
        """Pull out any content that appears to be injected via retrieved context."""
        docs = []
        for msg in messages:
            role    = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, str) and role in ("user", "assistant"):
                if "RETRIEVED CONTEXT" in content or "---" in content:
                    docs.append(content)
        return docs

    def _extract_user_message(self, messages: List[Dict]) -> str:
        """Return the last user message content."""
        for msg in reversed(messages):
            if msg.get("role") == "user" and isinstance(msg.get("content"), str):
                return msg["content"]
        return ""


class _ChatWrapper:
    def __init__(self, real_chat: Any, completions_wrapper: _CompletionsWrapper) -> None:
        self.completions = completions_wrapper
        self._real       = real_chat


class AgentCoCClient:
    """
    Drop-in replacement for `groq.Groq()`.

    Wraps the Groq client transparently so any existing agent gains
    AgentCoC's tamper-evident logging and injection detection without
    any other code changes.

    Example::

        # Before (any existing agent)
        from groq import Groq
        client = Groq(api_key=os.environ["GROQ_API_KEY"])

        # After (one line change)
        from agentcoc.wrapper import AgentCoCClient
        client = AgentCoCClient(api_key=os.environ["GROQ_API_KEY"])

        # Everything else stays identical
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[...],
        )

        # New: retrieve the forensic report
        result = client.get_session_result(generate_report=True)
    """

    def __init__(
        self,
        api_key:    Optional[str] = None,
        case_id:    str           = "session",
        output_dir: Path          = Path("reports"),
    ) -> None:
        _key = api_key or os.environ["GROQ_API_KEY"]

        self._groq          = Groq(api_key=_key)
        self._ledger        = EventLedger()
        self._interceptor   = EventInterceptor(self._ledger)
        self._detector      = InjectionDetector()
        self._reporter      = EvidentiaryReporter(output_dir=Path(output_dir))
        self._case_id       = case_id
        self._last_detection: Optional[DetectionResult] = None

        # Build the transparent wrapper chain
        completions_wrapper = _CompletionsWrapper(
            real_completions = self._groq.chat.completions,
            interceptor      = self._interceptor,
            detector         = self._detector,
            owner            = self,
        )
        self.chat = _ChatWrapper(self._groq.chat, completions_wrapper)

        # Forward any other Groq attributes transparently
        self._groq_ref = self._groq

    def get_session_result(
        self,
        generate_report: bool = True,
        user_message:    str  = "API session",
    ) -> SessionResult:
        """
        Return the complete forensic result for this session.

        Args:
            generate_report: If True, writes Rich terminal + HTML report.
            user_message:    Label for the report header.

        Returns:
            SessionResult with detection outcome and report path.
        """
        detection = self._last_detection

        if generate_report and detection is not None:
            report_path = self._reporter.generate(
                detection    = detection,
                ledger       = self._ledger,
                case_id      = self._case_id,
                user_message = user_message,
            )
        else:
            report_path = None

        return SessionResult(
            case_id        = self._case_id,
            flagged        = detection.flagged     if detection else False,
            confidence     = detection.confidence  if detection else "none",
            method         = detection.method      if detection else "none",
            chain_verified = self._ledger.verify_chain(),
            event_count    = len(self._ledger),
            report_path    = str(report_path) if report_path else None,
            detection      = detection,
            events         = [e.to_dict() for e in self._ledger.get_all()],
        )

    def __getattr__(self, name: str) -> Any:
        """Forward any unknown attributes to the real Groq client."""
        return getattr(self._groq_ref, name)
