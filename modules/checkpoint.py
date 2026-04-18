"""
modules/checkpoint.py — Checkpoint and resume system

After every phase completes, state is written to checkpoint.json.
If the terminal is killed (Ctrl+C, crash, disconnect), the next run
with --resume picks up exactly where it left off.

Checkpoint file location: <output_base>/<domain>/<timestamp>/checkpoint.json
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


CHECKPOINT_FILE = "checkpoint.json"
CHECKPOINT_VERSION = 1


class CheckpointError(RuntimeError):
    """Raised when a checkpoint file is corrupt or incompatible."""


class CheckpointManager:
    """Manages scan state persistence and resume logic."""

    def __init__(self, domain_dir: Path):
        self.domain_dir = domain_dir
        self.run_dir: Optional[Path] = None
        self.path: Optional[Path] = None
        self._state: dict = {
            "version":   CHECKPOINT_VERSION,
            "domain":    "",
            "started":   "",
            "completed": False,
            "phases":    {},
            "args":      {},
        }

    # ── Initialise a fresh run ────────────────────────────────
    def init(self, run_dir: Path, args):
        self.run_dir = run_dir
        self.path = run_dir / CHECKPOINT_FILE
        self._state["domain"]    = args.domain
        self._state["started"]   = datetime.now().isoformat()
        self._state["completed"] = False
        self._state["version"]   = CHECKPOINT_VERSION
        self._state["args"] = {
            "deep":          args.deep,
            "scan_scope":    args.scan_scope,
            "threads":       args.threads,
            "severity":      args.severity,
            "skip_nuclei":   args.skip_nuclei,
            "skip_portscan": args.skip_portscan,
            "skip_crawl":    args.skip_crawl,
        }
        self.save()

    # ── Load from an existing checkpoint file ─────────────────
    def load(self, run_dir: Path):
        self.run_dir = run_dir
        self.path = run_dir / CHECKPOINT_FILE

        if not self.path.exists():
            raise CheckpointError(f"Checkpoint file not found: {self.path}")

        raw = self.path.read_text()
        if not raw.strip():
            raise CheckpointError(f"Checkpoint file is empty: {self.path}")

        try:
            state = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CheckpointError(
                f"Checkpoint file is corrupt (JSON parse error): {self.path}\n"
                f"  Detail: {exc}\n"
                f"  Start a fresh scan without --resume or delete the file."
            ) from exc

        # Version check — future-proof
        ver = state.get("version", 0)
        if ver != CHECKPOINT_VERSION:
            raise CheckpointError(
                f"Checkpoint version mismatch: file has v{ver}, "
                f"expected v{CHECKPOINT_VERSION}. Start a fresh scan."
            )

        if "phases" not in state or not isinstance(state["phases"], dict):
            raise CheckpointError(
                f"Checkpoint file has unexpected format: {self.path}"
            )

        self._state = state

    # ── Persist state to disk ─────────────────────────────────
    def save(self):
        if not self.path:
            return
        self._state["last_saved"] = datetime.now().isoformat()
        # Atomic write: write to .tmp then rename to avoid partial files
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, indent=2))
        tmp.replace(self.path)

    # ── Mark a phase as complete with its output data ─────────
    def complete(self, phase: str, data: dict = None):
        self._state["phases"][phase] = {
            "done":      True,
            "completed": datetime.now().isoformat(),
            "data":      data or {},
        }
        self.save()

    # ── Query phase completion ─────────────────────────────────
    def is_done(self, phase: str) -> bool:
        return self._state["phases"].get(phase, {}).get("done", False)

    # ── Retrieve stored data from a completed phase ────────────
    def get(self, phase: str, key: str, default=None) -> Any:
        return self._state["phases"].get(phase, {}).get("data", {}).get(key, default or [])

    # ── Mark the full run as finished ─────────────────────────
    def mark_complete(self):
        self._state["completed"] = True
        self._state["finished"]  = datetime.now().isoformat()
        self.save()

    # ── Check if any phase data exists (for interrupt handler) ─
    def has_progress(self) -> bool:
        return bool(self._state.get("phases"))

    # ── Find the most recent incomplete run for this domain ────
    def find_resumable(self) -> Optional[Path]:
        """
        Scan all timestamped subdirectories of domain_dir.
        Return the path of the most recent one that has a valid checkpoint
        that is NOT marked as completed.
        """
        candidates = []
        for entry in sorted(self.domain_dir.iterdir(), reverse=True):
            if not entry.is_dir():
                continue
            cp = entry / CHECKPOINT_FILE
            if not cp.exists():
                continue
            try:
                state = json.loads(cp.read_text())
                if state.get("version") != CHECKPOINT_VERSION:
                    continue
                if not state.get("completed", False) and state.get("phases"):
                    candidates.append((entry, state))
            except Exception:
                continue

        if not candidates:
            return None

        best_dir, best_state = candidates[0]
        phases_done = [p for p, v in best_state.get("phases", {}).items() if v.get("done")]
        print(f"\n  Completed phases: {', '.join(phases_done) if phases_done else 'none'}")
        print(f"  Started:          {best_state.get('started', 'unknown')}")
        print(f"  Last saved:       {best_state.get('last_saved', 'unknown')}\n")
        return best_dir

    # ── Return args from the checkpoint (for resume display) ───
    def get_args_summary(self) -> dict:
        return self._state.get("args", {})
