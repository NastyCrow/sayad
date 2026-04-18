"""
modules/notify.py — Scan completion and critical-finding notifications

Supports:
  - macOS native (osascript)
  - Linux native (notify-send)
  - Slack incoming webhook
  - Discord webhook
"""

import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Optional


class Notifier:
    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
    ):
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook

    # ── Platform notification ─────────────────────────────────
    def _native(self, title: str, message: str):
        try:
            if sys.platform == "darwin":
                subprocess.run(
                    [
                        "osascript", "-e",
                        f'display notification "{_esc(message)}" with title "{_esc(title)}"',
                    ],
                    check=False, capture_output=True, timeout=5,
                )
            elif sys.platform.startswith("linux"):
                subprocess.run(
                    ["notify-send", "--urgency=normal", title, message],
                    check=False, capture_output=True, timeout=5,
                )
        except Exception:
            pass

    # ── Webhook ───────────────────────────────────────────────
    def _webhook(self, url: str, payload: dict):
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except (urllib.error.URLError, OSError):
            pass

    # ── Public API ────────────────────────────────────────────
    def send(self, title: str, message: str):
        self._native(title, message)
        if self.slack_webhook:
            self._webhook(self.slack_webhook, {
                "text": f"*{title}*\n{message}"
            })
        if self.discord_webhook:
            self._webhook(self.discord_webhook, {
                "content": f"**{title}**\n{message}"
            })

    def scan_complete(self, domain: str, stats: dict):
        subdomains    = stats.get("subdomains", 0)
        live_hosts    = stats.get("live_hosts", 0)
        findings      = stats.get("findings", 0)
        critical_high = stats.get("critical_high", 0)
        dork_hits     = stats.get("dork_hits", 0)

        title = (
            f"\U0001f6a8 {critical_high} Critical/High — {domain}"
            if critical_high > 0
            else f"\u2705 Recon Complete — {domain}"
        )
        parts = [
            f"Subdomains: {subdomains}",
            f"Live hosts: {live_hosts}",
            f"Nuclei findings: {findings} ({critical_high} crit/high)",
        ]
        if dork_hits:
            parts.append(f"GitHub exposure: {dork_hits} repos")
        self.send(title, " | ".join(parts))

    def critical_found(self, domain: str, finding: str):
        self.send(
            f"\U0001f6a8 Critical Finding — {domain}",
            finding[:200],
        )

    def phase_done(self, phase_name: str, domain: str, detail: str = ""):
        msg = f"Phase complete: {phase_name} ({domain})"
        if detail:
            msg += f"\n{detail}"
        self.send(f"Sayad — {phase_name} done", msg)


def _esc(s: str) -> str:
    """Escape special chars for osascript string literals."""
    return s.replace('"', '\\"').replace("\\", "\\\\")
