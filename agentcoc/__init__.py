"""
AgentCoC — Agent Chain of Custody
===================================
Forensic middleware for LLM agents: tamper-evident logging +
causal attribution + evidentiary standard scoring.

Quick start:
    from agentcoc import run_session

    result = run_session(
        user_message = "What is my account balance?",
        context_docs = [],        # inject malicious doc here for attack demo
        case_id      = "CASE-001",
    )
"""

from .ledger       import EventLedger
from .interceptor  import EventInterceptor
from .agent        import BankingAssistant
from .detector     import InjectionDetector
from .reporter     import EvidentiaryReporter
from .wrapper      import AgentCoCClient, SessionResult

__version__ = "1.0.0"
__author__  = "Olaolu Peter Adeniyi"

__all__ = [
    "EventLedger",
    "EventInterceptor",
    "BankingAssistant",
    "InjectionDetector",
    "AgentCoCClient",
    "SessionResult",
    "EvidentiaryReporter",
    "run_session",
]


def run_session(
    user_message: str,
    context_docs: list,
    case_id: str,
    output_dir: str = "reports",
) -> dict:
    """
    Convenience function: run a full AgentCoC session in one call.

    Wires together all 5 components and returns a summary dict.
    For fine-grained control, instantiate the components directly.

    Args:
        user_message: The user's query.
        context_docs: List of document strings (attack surface).
        case_id:      Unique ID for this incident.
        output_dir:   Where to write the HTML report.

    Returns:
        Dict with keys: flagged, confidence, report_path, chain_verified.
    """
    from pathlib import Path

    ledger      = EventLedger()
    interceptor = EventInterceptor(ledger)
    agent       = BankingAssistant()
    detector    = InjectionDetector()
    reporter    = EvidentiaryReporter(output_dir=Path(output_dir))

    # 1. Run the agent
    response = agent.run(
        user_message  = user_message,
        context_docs  = context_docs,
        interceptor   = interceptor,
    )

    # 2. Detect injection
    detection = detector.detect(
        user_message      = user_message,
        context_docs      = context_docs,
        original_response = response,
        interceptor       = interceptor,
        agent             = agent,
    )

    # 3. Generate report
    report_path = reporter.generate(
        detection    = detection,
        ledger       = ledger,
        case_id      = case_id,
        user_message = user_message,
    )

    return {
        "flagged":        detection.flagged,
        "confidence":     detection.confidence,
        "agent_response": response,
        "report_path":    str(report_path),
        "chain_verified": ledger.verify_chain(),
    }
