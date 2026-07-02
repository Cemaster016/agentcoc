"""
AgentCoC EventLedger
====================
Append-only, tamper-evident, hash-chained event log.

Each entry seals: event content + previous hash → SHA-256.
Integrity can be independently verified by replaying the chain.
This satisfies Stage 1 (Authentication) and Stage 4 (Chain of Custody)
of the FRE evidentiary gatekeeping test.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


GENESIS_HASH = "0" * 64  # Sentinel for the first entry


@dataclass
class LedgerEntry:
    """A single sealed, hash-chained event in the ledger."""

    event_id: str
    timestamp: str
    event_type: str
    content: Dict[str, Any]
    content_hash: str       # SHA-256 of the raw content JSON
    prev_hash: str          # SHA-256 of the previous entry (or GENESIS_HASH)
    entry_hash: str         # SHA-256 of (content_hash + prev_hash) — the seal

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventLedger:
    """
    Append-only tamper-evident event ledger.

    Entries are chained: each entry's seal includes the previous entry's hash,
    so any retroactive modification breaks the chain and is immediately
    detectable via verify_chain().

    Usage:
        ledger = EventLedger()
        ledger.append("tool_call", {"tool": "get_balance", "args": {...}})
        assert ledger.verify_chain()
        ledger.export("reports/incident.json")
    """

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self._entries: List[LedgerEntry] = []
        self._log_path = log_path  # if set, auto-persists on every append

    # ------------------------------------------------------------------ #
    #  Core methods                                                        #
    # ------------------------------------------------------------------ #

    def append(self, event_type: str, content: Dict[str, Any]) -> LedgerEntry:
        """
        Seal and append a new event to the ledger.

        Args:
            event_type: Category label (e.g. 'tool_call', 'llm_response',
                        'context_read', 'injection_flag', 'counterfactual').
            content:    Arbitrary dict describing the event.

        Returns:
            The sealed LedgerEntry (immutable after creation).
        """
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH

        content_json = json.dumps(content, sort_keys=True, ensure_ascii=False)
        content_hash = _sha256(content_json)
        entry_hash   = _sha256(content_hash + prev_hash)

        entry = LedgerEntry(
            event_id     = str(uuid.uuid4()),
            timestamp    = datetime.now(timezone.utc).isoformat(),
            event_type   = event_type,
            content      = content,
            content_hash = content_hash,
            prev_hash    = prev_hash,
            entry_hash   = entry_hash,
        )
        self._entries.append(entry)

        if self._log_path:
            self._persist()

        return entry

    def verify_chain(self) -> bool:
        """
        Replay the entire hash chain to verify ledger integrity.

        Returns:
            True if the chain is intact, False if any entry has been modified.
        """
        if not self._entries:
            return True

        prev_hash = GENESIS_HASH
        for entry in self._entries:
            # Re-derive the expected seal
            content_json    = json.dumps(entry.content, sort_keys=True, ensure_ascii=False)
            expected_c_hash = _sha256(content_json)
            expected_e_hash = _sha256(expected_c_hash + prev_hash)

            if entry.content_hash != expected_c_hash:
                return False
            if entry.entry_hash != expected_e_hash:
                return False
            if entry.prev_hash != prev_hash:
                return False

            prev_hash = entry.entry_hash

        return True

    # ------------------------------------------------------------------ #
    #  Accessors                                                           #
    # ------------------------------------------------------------------ #

    def get_all(self) -> List[LedgerEntry]:
        """Return all entries (read-only view)."""
        return list(self._entries)

    def get_by_type(self, event_type: str) -> List[LedgerEntry]:
        """Return entries filtered by event_type."""
        return [e for e in self._entries if e.event_type == event_type]

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def export(self, path: Path | str) -> Path:
        """
        Write the full ledger to a JSON file.

        Args:
            path: Destination file path.

        Returns:
            Resolved path to the written file.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ledger_version": "1.0",
            "chain_verified": self.verify_chain(),
            "entry_count":    len(self._entries),
            "entries":        [e.to_dict() for e in self._entries],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        return path.resolve()

    def _persist(self) -> None:
        """Auto-persist to log_path if set."""
        self.export(self._log_path)


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _sha256(data: str) -> str:
    """Return the hex-encoded SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
