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

import re
from pathlib import Path
from typing import List, Optional


# Maximum size of a custom scope file to load into memory (5 MB)
_MAX_SCOPE_FILE_BYTES = 5 * 1024 * 1024


class ScopeManager:
    def __init__(self, domain: str, live_hosts: list, cross_domain_redirects: list = None):
        self.domain = domain
        self.live_hosts = self._parse_hosts(live_hosts)
        # Set of probed URLs that redirect to an out-of-scope domain — excluded from
        # active scanning phases to avoid accidentally testing third-party infrastructure.
        self._cross_srcs: set = {src for src, _ in (cross_domain_redirects or [])}

    def _parse_hosts(self, raw: list) -> List[str]:
        """Extract base URLs from httpx output (handles 'https://sub.domain.com [200]' format)."""
        cleaned = []
        for line in raw:
            match = re.match(r'(https?://[^\s]+)', line)
            if match:
                cleaned.append(match.group(1).rstrip("/"))
        return cleaned

    def resolve(self, scope_arg: str, console=None) -> List[str]:
        """
        Resolve scope argument to a deduplicated list of target URLs/domains.
        """
        targets: List[str] = []

        if scope_arg == "main":
            targets = [f"https://{self.domain}", f"http://{self.domain}"]

        elif scope_arg == "all":
            if self.live_hosts:
                # Exclude hosts that redirect cross-domain — they would pull in
                # out-of-scope infrastructure during crawl/nuclei phases.
                filtered = [h for h in self.live_hosts if h not in self._cross_srcs]
                if self._cross_srcs and console:
                    console.print(
                        f"[yellow][!][/yellow] Excluded [bold]{len(self._cross_srcs)}[/bold] "
                        f"cross-domain redirect host(s) from active scope."
                    )
                targets = filtered if filtered else [f"https://{self.domain}"]
            else:
                targets = [f"https://{self.domain}"]

        elif scope_arg == "discovered":
            targets = self._interactive_select(console)

        else:
            # Custom file path — validate before use
            resolved = self._validate_scope_file(scope_arg, console)
            if resolved:
                targets = [
                    l.strip() for l in resolved.read_text().splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]
                if console:
                    console.print(
                        f"[green][+][/green] Loaded [bold]{len(targets)}[/bold] "
                        f"targets from [cyan]{resolved}[/cyan]"
                    )
            else:
                if console:
                    console.print(
                        f"[red][!][/red] Scope file not found or invalid: "
                        f"[bold]{scope_arg}[/bold] — falling back to main domain."
                    )
                targets = [f"https://{self.domain}"]

        # Deduplicate, remove empties
        seen: set = set()
        result: List[str] = []
        for t in targets:
            if t and t not in seen:
                seen.add(t)
                result.append(t)
        return result

    def _validate_scope_file(self, path_arg: str, console=None) -> Optional[Path]:
        """
        Validate a user-supplied scope file path.

        Checks:
        - Path exists and is a regular file (not a symlink to outside cwd, not a dir)
        - No directory-traversal components that escape reasonable bounds
        - File is not unreasonably large
        """
        try:
            p = Path(path_arg).resolve()
        except (ValueError, OSError):
            return None

        if not p.exists():
            return None

        if not p.is_file():
            if console:
                console.print(f"[red][!][/red] Scope path is not a regular file: {p}")
            return None

        # Guard against accidentally loading huge files into memory
        size = p.stat().st_size
        if size > _MAX_SCOPE_FILE_BYTES:
            if console:
                console.print(
                    f"[red][!][/red] Scope file is too large "
                    f"({size // 1024} KB > {_MAX_SCOPE_FILE_BYTES // 1024} KB limit): {p}"
                )
            return None

        return p

    def _interactive_select(self, console=None) -> List[str]:
        """
        Show a numbered list of live hosts and let the user pick.
        Accepts: comma-separated numbers, ranges (1-5), or 'all'
        """
        if not self.live_hosts:
            if console:
                console.print(
                    "[yellow][!][/yellow] No live hosts discovered — defaulting to main domain."
                )
            return [f"https://{self.domain}"]

        print("\n  Discovered live hosts:")
        print("  " + "─" * 60)
        for i, host in enumerate(self.live_hosts, 1):
            flag = "  ⚠  cross-domain redirect (excluded from auto-scope)" if host in self._cross_srcs else ""
            print(f"  [{i:>3}] {host}{flag}")
        print("  " + "─" * 60)
        print(f"  [  0] Main domain only  (https://{self.domain})")
        print()

        while True:
            try:
                raw = input(
                    "  Select targets (e.g. 1,3,5 or 1-10 or 'all' or 0 for main): "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return [f"https://{self.domain}"]

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

    def _parse_selection(self, raw: str, max_n: int) -> Optional[List[int]]:
        """
        Parse user input like '1,3,5-8' into a sorted list of integers.
        Returns None on invalid input. Clamps values to [1, max_n].
        """
        indices: set = set()
        try:
            for part in raw.split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    a_str, b_str = part.split("-", 1)
                    a, b = int(a_str), int(b_str)
                    if a > b:
                        return None
                    # Clamp to valid range
                    a = max(1, a)
                    b = min(max_n, b)
                    indices.update(range(a, b + 1))
                else:
                    n = int(part)
                    if 1 <= n <= max_n:
                        indices.add(n)
            return sorted(indices) if indices else None
        except ValueError:
            return None
