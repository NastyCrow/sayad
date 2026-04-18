"""
modules/config.py — Configuration and API key management

Keys are loaded from (in priority order):
  1. ~/.config/sayad/config.yaml
  2. Environment variables
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
    from rich.console import Console
    from rich.table import Table
except ImportError:
    pass

CONFIG_PATH = Path.home() / ".config" / "sayad" / "config.yaml"

# provider_name → (env_var, signup_url)
PROVIDERS = {
    "shodan":         ("SHODAN_API_KEY",         "account.shodan.io"),
    "virustotal":     ("VIRUSTOTAL_API_KEY",      "virustotal.com/gui/join-us"),
    "securitytrails": ("SECURITYTRAILS_API_KEY",  "securitytrails.com/app/signup"),
    "bevigil":        ("BEVIGIL_API_KEY",         "bevigil.com/osint-api"),
    "leakix":         ("LEAKIX_API_KEY",          "leakix.net/signup"),
}


@dataclass
class Config:
    # ── Recon API keys ────────────────────────────────────────
    shodan_api_key:         Optional[str] = None
    virustotal_api_key:     Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    bevigil_api_key:        Optional[str] = None
    leakix_api_key:         Optional[str] = None

    # ── GitHub dorking ────────────────────────────────────────
    github_token:           Optional[str] = None

    # ── Notifications ─────────────────────────────────────────
    slack_webhook:          Optional[str] = None
    discord_webhook:        Optional[str] = None

    suppress_warnings:      bool = False

    @classmethod
    def load(cls, suppress_warnings: bool = False) -> "Config":
        """Load config from YAML file, then overlay environment variables."""
        cfg = cls(suppress_warnings=suppress_warnings)
        file_data: dict = {}

        # ── Load from YAML ────────────────────────────────────
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH) as f:
                    loaded = yaml.safe_load(f)
                    file_data = loaded if isinstance(loaded, dict) else {}
            except yaml.YAMLError as exc:
                console = Console(stderr=True)
                console.print(
                    f"[yellow][!][/yellow] Could not parse config file "
                    f"[cyan]{CONFIG_PATH}[/cyan]: {exc}\n"
                    f"    Continuing without file-based config."
                )
            except OSError as exc:
                console = Console(stderr=True)
                console.print(
                    f"[yellow][!][/yellow] Could not read config file "
                    f"[cyan]{CONFIG_PATH}[/cyan]: {exc}"
                )

        # ── Key mapping: YAML field name → env var ────────────
        mapping = {
            "shodan_api_key":         "SHODAN_API_KEY",
            "virustotal_api_key":     "VIRUSTOTAL_API_KEY",
            "securitytrails_api_key": "SECURITYTRAILS_API_KEY",
            "bevigil_api_key":        "BEVIGIL_API_KEY",
            "leakix_api_key":         "LEAKIX_API_KEY",
            "github_token":           "GITHUB_TOKEN",
            "slack_webhook":          "SAYAD_SLACK_WEBHOOK",
            "discord_webhook":        "SAYAD_DISCORD_WEBHOOK",
        }

        for attr, env_var in mapping.items():
            val = file_data.get(attr) or file_data.get(env_var)
            val = os.environ.get(env_var) or val          # env wins over YAML
            if val and str(val).strip():
                setattr(cfg, attr, str(val).strip())

        return cfg

    @classmethod
    def create_template(cls):
        """Write a template config file if one doesn't exist."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text("""\
# Sayad Recon Framework — Configuration
# NEVER commit this file to Git.
# Place it at: ~/.config/sayad/config.yaml

# ── Recon API keys (optional, improves subdomain coverage) ──────────────
shodan_api_key: ""
virustotal_api_key: ""
securitytrails_api_key: ""
bevigil_api_key: ""
leakix_api_key: ""

# ── GitHub dorking (get a token at github.com/settings/tokens) ──────────
# Needs 'public_repo' read scope for code search.
github_token: ""

# ── Notifications (optional) ─────────────────────────────────────────────
# Slack:   create an Incoming Webhook at api.slack.com/apps
# Discord: Server Settings → Integrations → Webhooks
slack_webhook: ""
discord_webhook: ""
""")
            # Restrict permissions so API keys aren't world-readable
            try:
                CONFIG_PATH.chmod(0o600)
            except OSError:
                pass
            return True
        return False

    def get(self, provider: str) -> Optional[str]:
        """Get API key by provider name."""
        return getattr(self, f"{provider}_api_key", None)

    def active_count(self) -> int:
        return sum(1 for p in PROVIDERS if self.get(p))

    def print_key_status(self, suppress: bool = False):
        """Print a Rich table showing which API keys are configured."""
        console = Console()

        table = Table(
            title="API Key Status",
            border_style="dim",
            show_header=True,
            header_style="bold",
            title_style="bold cyan",
        )
        table.add_column("Service",     style="bold", width=18)
        table.add_column("Status",      width=14)
        table.add_column("Key Preview", width=24)
        table.add_column("Sign Up",     style="dim cyan")

        for name, (env_var, signup) in PROVIDERS.items():
            val = self.get(name)
            if val:
                masked = val[:6] + ("*" * 12)
                table.add_row(
                    name.capitalize(),
                    "[bold green]✓ Active[/bold green]",
                    f"[green]{masked}[/green]",
                    "",
                )
            elif suppress:
                table.add_row(name.capitalize(), "[dim]– Suppressed[/dim]", "", "")
            else:
                table.add_row(
                    name.capitalize(),
                    "[red]✗ Not set[/red]",
                    "",
                    signup,
                )

        console.print(table)

        active = self.active_count()
        console.print(f"  [bold]{active} / {len(PROVIDERS)} API keys active.[/bold]")

        # Show integration status (GitHub / notifications)
        extras = []
        if self.github_token:
            extras.append("[green]GitHub token ✓[/green]")
        if self.slack_webhook:
            extras.append("[green]Slack ✓[/green]")
        if self.discord_webhook:
            extras.append("[green]Discord ✓[/green]")
        if extras:
            console.print("  Integrations: " + "  ".join(extras))

        if active < len(PROVIDERS) and not suppress:
            console.print(
                f"  [yellow]Tip:[/yellow] Add keys to [cyan]{CONFIG_PATH}[/cyan] "
                f"or export as env vars.\n"
                f"  [yellow]Tip:[/yellow] Suppress with [bold]--no-api-warnings[/bold]"
            )
        console.print()
