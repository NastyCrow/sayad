"""
modules/scope.py — Scan scope control

Determines which targets are used for deep scanning phases
(crawling, parameter discovery, Nuclei).

Modes:
  main        → only the root domain (safest, default)
  all         → every discovered live host
  discovered  → interactive multi-select from live hosts
  <file.txt>  → read targets from a custom file
"""

from pathlib import Path
from typing import List


class ScopeManager:
    def __init__(self, domain: str, live_hosts: list):
        self.domain = domain
        # Extract clean hostnames/URLs from httpx output lines
        self.live_hosts = self._parse_hosts(live_hosts)

    def _parse_hosts(self, raw: list) -> List[str]:
        """Extract base URLs from httpx output (handles 'https://sub.domain.com [200]' format)."""
        import re
        cleaned = []
        for line in raw:
            # httpx output can be: https://host.com [200] [Title] ...
            match = re.match(r'(https?://[^\s]+)', line)
            if match:
                cleaned.append(match.group(1).rstrip("/"))
        return cleaned

    def resolve(self, scope_arg: str, console=None) -> List[str]:
        """
        Resolve scope argument to a list of target URLs/domains.

        Returns a deduplicated list of targets for deep scanning phases.
        """
        targets = []

        # ── main: only the root domain ────────────────────────
        if scope_arg == "main":
            targets = [f"https://{self.domain}", f"http://{self.domain}"]
            targets = [t for t in targets if t]

        # ── all: every discovered live host ───────────────────
        elif scope_arg == "all":
            targets = self.live_hosts if self.live_hosts else [f"https://{self.domain}"]

        # ── discovered: interactive selection ─────────────────
        elif scope_arg == "discovered":
            targets = self._interactive_select(console)

        # ── file path: read from custom file ──────────────────
        else:
            fpath = Path(scope_arg)
            if fpath.exists():
                targets = [l.strip() for l in fpath.read_text().splitlines() if l.strip()]
                if console:
                    console.print(f"[green][+][/green] Loaded [bold]{len(targets)}[/bold] targets from [cyan]{fpath}[/cyan]")
            else:
                if console:
                    console.print(f"[red][!][/red] Scope file not found: [bold]{scope_arg}[/bold] — falling back to main domain.")
                targets = [f"https://{self.domain}"]

        # Always deduplicate and remove empties
        seen = set()
        result = []
        for t in targets:
            if t and t not in seen:
                seen.add(t)
                result.append(t)

        return result

    def _interactive_select(self, console=None) -> List[str]:
        """
        Show a numbered list of live hosts and let the user pick.
        Accepts: comma-separated numbers, ranges (1-5), or 'all'
        """
        if not self.live_hosts:
            if console:
                console.print("[yellow][!][/yellow] No live hosts discovered yet — defaulting to main domain.")
            return [f"https://{self.domain}"]

        print("\n  Discovered live hosts:")
        print("  " + "─" * 50)
        for i, host in enumerate(self.live_hosts, 1):
            print(f"  [{i:>3}] {host}")
        print("  " + "─" * 50)
        print(f"  [  0] Main domain only  (https://{self.domain})")
        print()

        while True:
            raw = input(
                "  Select targets (e.g. 1,3,5 or 1-10 or 'all' or 0 for main): "
            ).strip().lower()

            if raw == "0":
                return [f"https://{self.domain}"]

            if raw == "all":
                return self.live_hosts

            selected = self._parse_selection(raw, len(self.live_hosts))
            if selected is None:
                print("  [!] Invalid input — try again.")
                continue

            targets = [self.live_hosts[i - 1] for i in selected if 0 < i <= len(self.live_hosts)]
            if not targets:
                print("  [!] No valid targets selected — try again.")
                continue

            print(f"\n  Selected {len(targets)} target(s):")
            for t in targets:
                print(f"    → {t}")
            print()
            return targets

    def _parse_selection(self, raw: str, max_n: int):
        """Parse user input like '1,3,5-8' into a list of integers."""
        indices = set()
        try:
            for part in raw.split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-", 1)
                    indices.update(range(int(a), int(b) + 1))
                else:
                    indices.add(int(part))
            return sorted(indices)
        except ValueError:
            return None