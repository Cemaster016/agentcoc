"""
AgentCoC EvidentiaryReporter
==============================
Scores a DetectionResult + EventLedger against the four-stage
FRE evidentiary gatekeeping test, then renders two outputs:

  1. Rich terminal table — immediate human-readable verdict
  2. HTML incident report — archivable, shareable forensic document

The four stages (from the research framework):
  Stage 1 — Authentication (FRE 901/902): is the evidence provably untampered?
  Stage 2 — Reliability (Daubert): is the attribution method scientifically validated?
  Stage 3 — Relevance: does it answer the causal "why", not just "where"?
  Stage 4 — Chain of custody: is the ENTIRE trace accounted for?
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .detector import DetectionResult
from .ledger import EventLedger


# ------------------------------------------------------------------ #
#  Verdict enum                                                       #
# ------------------------------------------------------------------ #

class Verdict(str, Enum):
    PASS        = "PASS"
    PARTIAL     = "PARTIAL"
    FAIL        = "FAIL"
    CONDITIONAL = "CONDITIONAL"


_VERDICT_COLORS = {
    Verdict.PASS:        "green",
    Verdict.PARTIAL:     "yellow",
    Verdict.FAIL:        "red",
    Verdict.CONDITIONAL: "orange3",
}

_VERDICT_EMOJI = {
    Verdict.PASS:        "✅",
    Verdict.PARTIAL:     "⚠️",
    Verdict.FAIL:        "❌",
    Verdict.CONDITIONAL: "🔶",
}

# HTML colours for the report
_VERDICT_HTML_COLORS = {
    Verdict.PASS:        "#2E7D32",
    Verdict.PARTIAL:     "#E65100",
    Verdict.FAIL:        "#B71C1C",
    Verdict.CONDITIONAL: "#F57F17",
}


# ------------------------------------------------------------------ #
#  Stage result dataclass                                             #
# ------------------------------------------------------------------ #

@dataclass
class StageResult:
    stage_number: int
    stage_name:   str
    legal_basis:  str
    verdict:      Verdict
    finding:      str   # one-sentence verdict explanation
    detail:       str   # fuller forensic analysis


# ------------------------------------------------------------------ #
#  EvidentiaryReporter                                                #
# ------------------------------------------------------------------ #

class EvidentiaryReporter:
    """
    Applies the four-stage FRE evidentiary gatekeeping test to an incident.

    Usage:
        reporter = EvidentiaryReporter(output_dir=Path("reports"))
        reporter.generate(
            detection   = detection_result,
            ledger      = event_ledger,
            case_id     = "CASE-001",
            user_message = "What is my balance?",
        )
    """

    def __init__(self, output_dir: Path = Path("reports")) -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._console = Console()

    # ---------------------------------------------------------------- #
    #  Main entry point                                                 #
    # ---------------------------------------------------------------- #

    def generate(
        self,
        detection:    DetectionResult,
        ledger:       EventLedger,
        case_id:      str,
        user_message: str,
    ) -> Path:
        """
        Score the incident and produce terminal + HTML outputs.

        Args:
            detection:    Result from InjectionDetector.
            ledger:       The complete tamper-evident event ledger.
            case_id:      Unique identifier for this incident.
            user_message: The original user query that triggered the session.

        Returns:
            Path to the generated HTML report file.
        """
        stages = self._score_all_stages(detection, ledger)
        report_path = self._render_html(detection, ledger, stages, case_id, user_message)
        self._render_terminal(detection, stages, case_id, user_message, report_path)
        return report_path

    # ---------------------------------------------------------------- #
    #  4-Stage scoring                                                  #
    # ---------------------------------------------------------------- #

    def _score_all_stages(
        self,
        detection: DetectionResult,
        ledger:    EventLedger,
    ) -> List[StageResult]:
        return [
            self._score_stage1(ledger),
            self._score_stage2(detection),
            self._score_stage3(detection),
            self._score_stage4(ledger),
        ]

    def _score_stage1(self, ledger: EventLedger) -> StageResult:
        """
        Stage 1 — Authentication (FRE 901/902)
        Can the proponent prove this evidence is what it claims to be?
        → Verify the SHA-256 hash chain is unbroken.
        """
        chain_valid   = ledger.verify_chain()
        entry_count   = len(ledger)
        latest_hash   = ledger.get_all()[-1].entry_hash if ledger.get_all() else "N/A"

        if chain_valid:
            verdict = Verdict.PASS
            finding = "Hash chain is intact across all events — evidence is verifiably untampered."
            detail  = (
                f"The EventLedger contains {entry_count} sealed entries. "
                f"SHA-256 hash chain replay confirmed integrity end-to-end. "
                f"Terminal hash: {latest_hash[:16]}… "
                "This satisfies FRE 901(b)(9) (process or system producing accurate result) "
                "and FRE 902 self-authentication via cryptographic seal."
            )
        else:
            verdict = Verdict.FAIL
            finding = "Hash chain verification FAILED — the ledger has been modified after the fact."
            detail  = (
                "At least one entry's recomputed hash does not match its stored hash. "
                "This evidence cannot be authenticated and would be inadmissible under FRE 901. "
                "The modification point should be investigated as a separate incident."
            )

        return StageResult(1, "Authentication", "FRE 901/902", verdict, finding, detail)

    def _score_stage2(self, detection: DetectionResult) -> StageResult:
        """
        Stage 2 — Reliability (Daubert v. Merrell Dow, 509 U.S. 579)
        Is the methodology scientifically valid with known, tested error rates?
        → Counterfactual replay is sound in principle, but lacks a peer-reviewed
          false-positive rate. This is the critical gap identified by the research.
        """
        if detection.counterfactual_ran and detection.diverged:
            verdict = Verdict.PARTIAL
            finding = (
                "Counterfactual replay confirms causal attribution, but no peer-reviewed "
                "error rate exists for this method — Daubert reliability is PARTIAL."
            )
            detail  = (
                "The counterfactual methodology (re-run without suspected injection → compare) "
                "is logically sound and mirrors accepted causal inference practice. "
                "However, Daubert requires a known, tested error rate and peer-review. "
                "Current tools (AttriGuard, AgentSentry) report confidence scores, not "
                "validated FP/FN rates across held-out ground-truth datasets. "
                "RECOMMENDATION: Validate attribution error rates on a labelled AgentDojo "
                "split before using this as standalone legal evidence."
            )
        elif detection.heuristic_triggered and not detection.counterfactual_ran:
            verdict = Verdict.PARTIAL
            finding = "Heuristic detection only — counterfactual replay not attempted. Reliability is PARTIAL."
            detail  = (
                "Pattern matching detected an injection candidate, but causal attribution via "
                "counterfactual replay was not executed. Without replay, the attribution is "
                "observational rather than causal. Daubert requires testable methodology; "
                "heuristics alone do not meet this standard."
            )
        else:
            verdict = Verdict.FAIL
            finding = "No injection detected — reliability assessment N/A for this session."
            detail  = "No attribution method was triggered. Stage 2 is not applicable."

        return StageResult(2, "Reliability", "Daubert standard", verdict, finding, detail)

    def _score_stage3(self, detection: DetectionResult) -> StageResult:
        """
        Stage 3 — Relevance
        Does the evidence actually resolve the disputed causal question?
        → Attribution must answer "why the agent acted" not just "where the input was."
        """
        if not detection.flagged:
            return StageResult(
                3, "Relevance", "FRE 401/402",
                Verdict.PASS,
                "No injection — no causal question to resolve. Clean session.",
                "No anomalous causal chain was detected. The agent's actions are attributable "
                "entirely to the authenticated user's explicit instruction."
            )

        if detection.diverged:
            verdict = Verdict.PARTIAL
            finding = (
                "Attribution identifies the causal input (where), but cannot fully explain "
                "why the agent's policy treated the injection as trusted instruction."
            )
            detail  = (
                f"The counterfactual replay confirmed that removing the flagged content "
                f"('…{detection.flagged_content[:60]}…') changed the agent's output. "
                "This answers the 'which input caused the deviation' question. "
                "However, it does not fully explain the model's internal trust mechanism — "
                "i.e., why the system prompt's security rules were overridden. "
                "A full mechanistic explanation (attention weights, layer attribution) would "
                "be needed to fully satisfy the causal 'why' for legal proceedings."
            )
        else:
            verdict = Verdict.PARTIAL
            finding = "Pattern matched, but outputs did not diverge — causal link is inconclusive."
            detail  = (
                "An injection pattern was detected in the context, but removing it did not "
                "change the agent's output. This weakens the causal relevance argument. "
                "The agent may have already had the instruction from another source, or the "
                "model ignored the injection. Relevance is partial at best."
            )

        return StageResult(3, "Relevance", "FRE 401/402", verdict, finding, detail)

    def _score_stage4(self, ledger: EventLedger) -> StageResult:
        """
        Stage 4 — Chain of Custody (ACPO/PACE / ISO 27037)
        Is the ENTIRE sequence of events accounted for with no gaps?
        → Check that all required event types are present in the ledger.
        """
        all_types  = {e.event_type for e in ledger.get_all()}
        chain_ok   = ledger.verify_chain()

        # Required event types for a complete custody record
        required_types = {"context_read", "llm_call", "tool_call"}
        present_types  = required_types & all_types
        missing_types  = required_types - all_types

        has_counterfactual = "counterfactual" in all_types
        has_flag           = "injection_flag" in all_types

        if chain_ok and not missing_types and has_counterfactual:
            verdict = Verdict.PASS
            finding = "Complete, unbroken event chain — all mandatory event types present and hash-verified."
            detail  = (
                f"All {len(ledger)} events are sealed and hash-chained. "
                f"Event types recorded: {sorted(all_types)}. "
                "The chain runs from initial context ingestion through LLM inference, "
                "tool execution, injection detection, and counterfactual replay. "
                "No gaps detected. This satisfies ISO/IEC 27037:2012 digital evidence "
                "guidelines and ACPO Principle 1 (no alteration of original evidence)."
            )
        elif chain_ok and not missing_types and not has_counterfactual:
            verdict = Verdict.CONDITIONAL
            finding = (
                "Chain is complete for standard actions, but counterfactual replay "
                "events are absent — custody is CONDITIONAL on whether replay was needed."
            )
            detail  = (
                f"Event types present: {sorted(all_types)}. "
                "No injection was detected so no counterfactual was run. "
                "If this session is later disputed, the absence of a replay event means "
                "the chain is complete but cannot prove absence of injection causation. "
                "RECOMMENDATION: Run InjectionDetector on all sessions, even clean ones, "
                "to produce a complete negative finding record."
            )
        elif missing_types:
            verdict = Verdict.PARTIAL
            finding = f"Chain is missing event types: {missing_types} — custody record is incomplete."
            detail  = (
                f"Expected event types {required_types} but only found {present_types}. "
                "Missing events represent gaps in the custody record that could be challenged "
                "in legal proceedings as evidence that events occurred outside the monitored scope."
            )
        else:
            verdict = Verdict.FAIL
            finding = "Hash chain broken AND missing event types — chain of custody fails."
            detail  = "The ledger cannot verify integrity and is missing critical event types."

        return StageResult(4, "Chain of Custody", "ACPO / ISO 27037", verdict, finding, detail)

    # ---------------------------------------------------------------- #
    #  Rich terminal output                                             #
    # ---------------------------------------------------------------- #

    def _render_terminal(
        self,
        detection:   DetectionResult,
        stages:      List[StageResult],
        case_id:     str,
        user_message: str,
        report_path: Path,
    ) -> None:
        console = self._console

        # Header
        console.print()
        console.rule("[bold cyan]AgentCoC — Evidentiary Incident Report[/bold cyan]")
        console.print(f"[bold]Case ID:[/bold]      {case_id}")
        console.print(f"[bold]Timestamp:[/bold]    {datetime.now(timezone.utc).isoformat()}")
        console.print(f"[bold]User Query:[/bold]   {user_message[:80]}…" if len(user_message) > 80 else f"[bold]User Query:[/bold]   {user_message}")
        console.print()

        # Injection summary
        if detection.flagged:
            status_text = Text("⚠️  PROMPT INJECTION DETECTED", style="bold red")
            console.print(Panel(
                f"{status_text}\n\n"
                f"[bold]Summary:[/bold]     {detection.summary}\n"
                f"[bold]Method:[/bold]      {detection.method}\n"
                f"[bold]Confidence:[/bold]  {detection.confidence}\n"
                f"[bold]Flagged:[/bold]     {detection.flagged_content[:80]}",
                title="Detection Result",
                border_style="red",
            ))
        else:
            console.print(Panel(
                "✅  [bold green]No injection detected — clean session.[/bold green]\n\n"
                f"[bold]Summary:[/bold] {detection.summary}",
                title="Detection Result",
                border_style="green",
            ))

        console.print()

        # 4-Stage scoring table
        table = Table(
            title="4-Stage Evidentiary Gatekeeping Assessment",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_blue",
            expand=True,
        )
        table.add_column("Stage", style="bold", width=6,  justify="center")
        table.add_column("Name",  width=22)
        table.add_column("Legal Basis", width=20)
        table.add_column("Verdict", width=14, justify="center")
        table.add_column("Finding", no_wrap=False)

        for s in stages:
            color   = _VERDICT_COLORS[s.verdict]
            emoji   = _VERDICT_EMOJI[s.verdict]
            verdict = Text(f"{emoji} {s.verdict.value}", style=f"bold {color}")
            table.add_row(str(s.stage_number), s.stage_name, s.legal_basis, verdict, s.finding)

        console.print(table)
        console.print()
        console.print(f"[dim]📄 Full HTML report saved to: {report_path}[/dim]")
        console.print()
        console.rule("[dim cyan]End of Report[/dim cyan]")
        console.print()

    # ---------------------------------------------------------------- #
    #  HTML report                                                      #
    # ---------------------------------------------------------------- #

    def _render_html(
        self,
        detection:    DetectionResult,
        ledger:       EventLedger,
        stages:       List[StageResult],
        case_id:      str,
        user_message: str,
    ) -> Path:
        html = _build_html(detection, ledger, stages, case_id, user_message)
        path = self._output_dir / f"incident_{case_id}.html"
        path.write_text(html, encoding="utf-8")
        return path.resolve()


# ------------------------------------------------------------------ #
#  HTML builder — legal-grade report with PDF print support          #
# ------------------------------------------------------------------ #

def _build_html(
    detection:    DetectionResult,
    ledger:       EventLedger,
    stages:       List[StageResult],
    case_id:      str,
    user_message: str,
) -> str:
    ts          = datetime.now(timezone.utc).isoformat()
    chain_ok    = ledger.verify_chain()
    det_label   = "⚠ PROMPT INJECTION DETECTED" if detection.flagged else "✅ CLEAN SESSION — No Injection Detected"
    det_color   = "#7F1D1D" if detection.flagged else "#1B5E20"
    det_bg      = "#FFF5F5" if detection.flagged else "#F0FFF4"
    det_border  = "#FCA5A5" if detection.flagged else "#86EFAC"
    det_icon    = "⚠️" if detection.flagged else "✅"

    # Pre-compute flagged pills to avoid nested f-string escaping
    if detection.flagged:
        content_pill = ""
        if detection.flagged_content:
            content_pill = f'<span class="dpill">Flagged: &ldquo;{detection.flagged_content[:60]}&hellip;&rdquo;</span>'
        flagged_pills = (
            f'<div class="detect-pills">'
            f'<span class="dpill">Confidence: {detection.confidence.upper()}</span>'
            f'<span class="dpill">Method: {detection.method}</span>'
            f'{content_pill}</div>'
        )
    else:
        flagged_pills = ""

    verdict_styles = {
        Verdict.PASS:        ("PASS",        "#1B5E20", "#E8F5E9", "#81C784"),
        Verdict.PARTIAL:     ("PARTIAL",     "#BF360C", "#FBE9E7", "#FF8A65"),
        Verdict.FAIL:        ("FAIL",        "#7F1D1D", "#FFEBEE", "#EF9A9A"),
        Verdict.CONDITIONAL: ("CONDITIONAL", "#E65100", "#FFF3E0", "#FFB74D"),
    }

    # Stage blocks
    stage_blocks = ""
    for s in stages:
        label, color, bg, border = verdict_styles[s.verdict]
        stage_blocks += f"""
        <div class="stage-block" style="background:{bg};border-color:{border}">
          <div class="stage-header">
            <div>
              <span class="stage-num">Stage {s.stage_number}</span>
              <span class="stage-name">{s.stage_name}</span>
              <span class="stage-law">{s.legal_basis}</span>
            </div>
            <div class="stage-verdict" style="color:{color}">{_VERDICT_EMOJI[s.verdict]} {label}</div>
          </div>
          <div class="stage-finding">{s.finding}</div>
          <div class="stage-detail">{s.detail}</div>
        </div>"""

    # Ledger table rows
    ledger_rows = ""
    for i, e in enumerate(ledger.get_all(), 1):
        ledger_rows += f"""
        <tr class="{'row-alt' if i%2==0 else ''}">
          <td class="mono">{i}</td>
          <td class="mono" style="color:#555">{e.timestamp}</td>
          <td><span class="etype">{e.event_type}</span></td>
          <td class="mono hash">{e.entry_hash[:32]}…</td>
          <td class="preview">{json.dumps(e.content)[:100]}…</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AgentCoC Incident Report — {case_id}</title>
<style>
/* ── Base ─────────────────────────────────────────────────────────── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --teal:#00695C;--teal-l:#E0F2F1;
  --text:#111827;--muted:#6B7280;--border:#D1D5DB;
  --bg:#F4F6F9;--surface:#fff;
}}
body{{font-family:Georgia,'Times New Roman',serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.65}}
.page{{max-width:900px;margin:32px auto;background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}}

/* ── Toolbar (screen only) ────────────────────────────────────────── */
.toolbar{{background:#1C2B3A;padding:12px 28px;display:flex;align-items:center;justify-content:space-between}}
.toolbar-title{{color:#94A3B8;font-family:system-ui,sans-serif;font-size:.82rem;font-weight:600;letter-spacing:.3px}}
.toolbar-btns{{display:flex;gap:8px}}
.tbtn{{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border-radius:5px;font-family:system-ui,sans-serif;font-size:.8rem;font-weight:700;cursor:pointer;border:none;transition:all .15s}}
.tbtn-primary{{background:#00897B;color:#fff}}
.tbtn-primary:hover{{background:#00695C}}
.tbtn-ghost{{background:transparent;color:#94A3B8;border:1px solid #334155}}
.tbtn-ghost:hover{{background:#243447;color:#fff}}

/* ── Report header ────────────────────────────────────────────────── */
.rpt-header{{background:var(--teal);color:#fff;padding:28px 36px 22px}}
.rpt-org{{font-family:system-ui,sans-serif;font-size:.75rem;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;opacity:.8;margin-bottom:8px}}
.rpt-title{{font-size:1.45rem;font-weight:700;letter-spacing:-.3px;margin-bottom:6px}}
.rpt-subtitle{{font-size:.88rem;opacity:.85}}

/* ── Meta grid ────────────────────────────────────────────────────── */
.meta-section{{padding:20px 36px;background:#F8FAFB;border-bottom:2px solid var(--border)}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px 32px}}
.meta-row{{display:flex;flex-direction:column;gap:2px}}
.meta-label{{font-family:system-ui,sans-serif;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}}
.meta-value{{font-size:.9rem;color:var(--text)}}
.meta-value.mono{{font-family:'Courier New',monospace;font-size:.82rem;word-break:break-all}}

/* ── Detection banner ─────────────────────────────────────────────── */
.detect-section{{padding:20px 36px;border-bottom:2px solid var(--border)}}
.detect-box{{background:{det_bg};border:1.5px solid {det_border};border-radius:5px;padding:16px 20px;display:flex;gap:16px;align-items:flex-start}}
.detect-icon{{font-size:1.6rem;line-height:1;flex-shrink:0}}
.detect-label{{font-family:system-ui,sans-serif;font-size:.95rem;font-weight:800;color:{det_color};margin-bottom:4px}}
.detect-summary{{font-size:.88rem;color:var(--muted)}}
.detect-pills{{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}}
.dpill{{font-family:system-ui,sans-serif;font-size:.72rem;font-weight:700;padding:3px 10px;border-radius:20px;background:#fff;border:1px solid {det_border};color:{det_color}}}

/* ── Section headings ─────────────────────────────────────────────── */
.section{{padding:24px 36px;border-bottom:1px solid var(--border)}}
.section:last-child{{border-bottom:none}}
.section-title{{font-family:system-ui,sans-serif;font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:1.2px;color:var(--teal);margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid var(--teal-l)}}

/* ── Stage blocks ─────────────────────────────────────────────────── */
.stage-block{{border:1.5px solid #D1D5DB;border-radius:6px;padding:16px 18px;margin-bottom:12px}}
.stage-block:last-child{{margin-bottom:0}}
.stage-header{{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}}
.stage-num{{font-family:system-ui,sans-serif;font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);display:block;margin-bottom:2px}}
.stage-name{{font-family:system-ui,sans-serif;font-size:.95rem;font-weight:800;display:block;margin-bottom:2px}}
.stage-law{{font-size:.8rem;color:var(--muted);font-style:italic}}
.stage-verdict{{font-family:system-ui,sans-serif;font-size:1rem;font-weight:800;white-space:nowrap;flex-shrink:0}}
.stage-finding{{font-size:.88rem;font-weight:600;margin-bottom:8px;color:var(--text)}}
.stage-detail{{font-size:.83rem;color:#4B5563;line-height:1.6;padding-top:8px;border-top:1px solid rgba(0,0,0,.07)}}

/* ── Ledger table ─────────────────────────────────────────────────── */
.ledger-table{{width:100%;border-collapse:collapse;font-size:.78rem}}
.ledger-table th{{background:var(--teal);color:#fff;padding:8px 10px;text-align:left;font-family:system-ui,sans-serif;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}}
.ledger-table td{{padding:7px 10px;border-bottom:1px solid #F3F4F6;vertical-align:top}}
.row-alt td{{background:#FAFAFA}}
.mono{{font-family:'Courier New',monospace}}
.hash{{font-size:.72rem;color:#9CA3AF;word-break:break-all}}
.preview{{color:#6B7280;font-size:.75rem}}
.etype{{background:#F3F4F6;border-radius:3px;padding:2px 7px;font-family:system-ui,sans-serif;font-size:.72rem;font-weight:600;color:#374151}}

/* ── Signature block ──────────────────────────────────────────────── */
.sig-section{{padding:24px 36px;background:#F8FAFB;border-top:2px solid var(--border)}}
.sig-grid{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:24px;margin-top:16px}}
.sig-box{{border-top:1px solid #374151;padding-top:8px}}
.sig-role{{font-family:system-ui,sans-serif;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}}
.sig-space{{height:40px}}

/* ── Footer ───────────────────────────────────────────────────────── */
.rpt-footer{{background:#1C2B3A;color:#64748B;padding:14px 36px;font-family:system-ui,sans-serif;font-size:.72rem;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}}
.rpt-footer a{{color:#94A3B8;text-decoration:none}}

/* ── Print / PDF ──────────────────────────────────────────────────── */
@media print{{
  body{{background:#fff;font-size:11pt}}
  .toolbar,.tbtn{{display:none!important}}
  .page{{max-width:100%;margin:0;border:none;border-radius:0;box-shadow:none}}
  .rpt-header{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .stage-block{{page-break-inside:avoid}}
  .ledger-table th{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .section{{page-break-inside:avoid}}
  @page{{size:A4;margin:18mm 14mm}}
}}
</style>
<script>
// Auto-trigger print if ?pdf=1 is in URL
window.addEventListener('load', function(){{
  if(new URLSearchParams(location.search).get('pdf')==='1') setTimeout(()=>window.print(),600);
}});
</script>
</head>
<body>
<div class="page">

  <!-- Toolbar (hidden when printing) -->
  <div class="toolbar">
    <span class="toolbar-title">AgentCoC &nbsp;·&nbsp; Incident Report &nbsp;·&nbsp; {case_id}</span>
    <div class="toolbar-btns">
      <button class="tbtn tbtn-ghost" onclick="window.close()">✕ &nbsp;Close</button>
      <button class="tbtn tbtn-primary" onclick="window.print()">⬇️ &nbsp;Download PDF</button>
    </div>
  </div>

  <!-- Report header -->
  <div class="rpt-header">
    <div class="rpt-org">AgentCoC &nbsp;·&nbsp; Forensic AI Middleware &nbsp;·&nbsp; Deep Learning Indaba 2026 &nbsp;·&nbsp; Poster GP-32</div>
    <div class="rpt-title">Evidentiary Incident Report</div>
    <div class="rpt-subtitle">FRE 901/902 &nbsp;·&nbsp; Daubert Standard &nbsp;·&nbsp; ACPO/ISO 27037 &nbsp;·&nbsp; EU AI Act Article 12</div>
  </div>

  <!-- Metadata -->
  <div class="meta-section">
    <div class="meta-grid">
      <div class="meta-row"><span class="meta-label">Case Reference</span><span class="meta-value mono">{case_id}</span></div>
      <div class="meta-row"><span class="meta-label">Report Generated</span><span class="meta-value">{ts}</span></div>
      <div class="meta-row"><span class="meta-label">User Query</span><span class="meta-value">{user_message}</span></div>
      <div class="meta-row"><span class="meta-label">Events Sealed</span><span class="meta-value">{len(ledger)}</span></div>
      <div class="meta-row"><span class="meta-label">Chain Integrity</span><span class="meta-value">{'✅ SHA-256 chain verified — untampered' if chain_ok else '❌ CHAIN BROKEN — evidence may be compromised'}</span></div>
      <div class="meta-row"><span class="meta-label">Detection Method</span><span class="meta-value">{detection.method}</span></div>
    </div>
  </div>

  <!-- Detection verdict -->
  <div class="detect-section">
    <div class="detect-box">
      <div class="detect-icon">{det_icon}</div>
      <div>
        <div class="detect-label">{det_label}</div>
        <div class="detect-summary">{detection.summary}</div>
        {flagged_pills}
      </div>
    </div>
  </div>

  <!-- 4-Stage assessment -->
  <div class="section">
    <div class="section-title">4-Stage Evidentiary Gatekeeping Assessment</div>
    {stage_blocks}
  </div>

  <!-- Ledger -->
  <div class="section">
    <div class="section-title">Tamper-Evident Event Ledger &nbsp;({len(ledger)} entries)</div>
    <table class="ledger-table">
      <thead>
        <tr><th>#</th><th>Timestamp (UTC)</th><th>Event Type</th><th>Entry Hash (SHA-256, truncated)</th><th>Content Preview</th></tr>
      </thead>
      <tbody>{ledger_rows}</tbody>
    </table>
  </div>

  <!-- Signature block -->
  <div class="sig-section">
    <div class="section-title">Certification &amp; Signature</div>
    <p style="font-size:.85rem;color:#4B5563;margin-bottom:16px">
      This report was generated automatically by AgentCoC v1.0. The tamper-evident hash chain above
      constitutes a cryptographically verifiable record of all agent actions. Any alteration of the
      ledger will cause hash chain verification to fail and must be treated as evidence tampering.
    </p>
    <div class="sig-grid">
      <div class="sig-box">
        <div class="sig-space"></div>
        <div class="sig-role">Investigating Officer</div>
      </div>
      <div class="sig-box">
        <div class="sig-space"></div>
        <div class="sig-role">Legal Counsel</div>
      </div>
      <div class="sig-box">
        <div class="sig-space"></div>
        <div class="sig-role">Technical Witness</div>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <div class="rpt-footer">
    <span>Generated by AgentCoC v1.0 &nbsp;·&nbsp; <a href="https://deeplearningindaba.com">Deep Learning Indaba 2026</a> &nbsp;·&nbsp; Poster GP-32</span>
    <span>FRE 901/902 &nbsp;·&nbsp; Daubert v. Merrell Dow (1993) &nbsp;·&nbsp; EU AI Act Art. 12 &nbsp;·&nbsp; ISO/IEC 27037:2012</span>
  </div>

</div>
</body>
</html>"""
