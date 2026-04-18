"""
modules/config.py — Configuration and API key management
Keys are loaded from (in priority order):
  1. ~/.config/sayad/config.yaml
  2. Environment variables
"""

import os
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

PROVIDERS = {
    "shodan":          ("SHODAN_API_KEY",         "account.shodan.io"),
    "virustotal":      ("VIRUSTOTAL_API_KEY",      "virustotal.com/gui/join-us"),
    "securitytrails":  ("SECURITYTRAILS_API_KEY",  "securitytrails.com/app/signup"),
    "bevigil":         ("BEVIGIL_API_KEY",         "bevigil.com/osint-api"),
    "leakix":          ("LEAKIX_API_KEY",          "leakix.net/signup"),
}


@dataclass
class Config:
    shodan_api_key:         Optional[str] = None
    virustotal_api_key:     Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    bevigil_api_key:        Optional[str] = None
    leakix_api_key:         Optional[str] = None
    suppress_warnings:      bool = False

    @classmethod
    def load(cls, suppress_warnings: bool = False) -> "Config":
        """Load config from YAML file first, then overlay environment variables."""
        cfg = cls(suppress_warnings=suppress_warnings)
        file_data = {}

        # ── Load from YAML if it exists ───────────────────────
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH) as f:
                    file_data = yaml.safe_load(f) or {}
            except Exception:
                pass

        # ── Map keys: YAML → dataclass field, then env override ──
        mapping = {
            "shodan_api_key":         "SHODAN_API_KEY",
            "virustotal_api_key":     "VIRUSTOTAL_API_KEY",
            "securitytrails_api_key": "SECURITYTRAILS_API_KEY",
            "bevigil_api_key":        "BEVIGIL_API_KEY",
            "leakix_api_key":         "LEAKIX_API_KEY",
        }

        for attr, env_var in mapping.items():
            # YAML value
            yaml_key = attr  # same name in yaml
            val = file_data.get(yaml_key) or file_data.get(env_var)
            # Environment variable wins over YAML
            val = os.environ.get(env_var) or val
            if val:
                setattr(cfg, attr, str(val).strip())

        return cfg

    @classmethod
    def create_template(cls):
        """Write a template config file if one doesn't exist."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text("""\
# Sayad Recon Framework — API Keys Configuration
# Place your API keys here. This file is only read by you locally.
# NEVER commit this file to Git.

shodan_api_key: ""
virustotal_api_key: ""
securitytrails_api_key: ""
bevigil_api_key: ""
leakix_api_key: ""
""")
            return True
        return False

    def get(self, provider: str) -> Optional[str]:
        """Get API key by provider name."""
        attr = f"{provider}_api_key"
        return getattr(self, attr, None)

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
            title_style="bold cyan"
        )
        table.add_column("Service", style="bold", width=18)
        table.add_column("Status", width=14)
        table.add_column("Key Preview", width=24)
        table.add_column("Sign Up", style="dim cyan")

        for name, (env_var, signup) in PROVIDERS.items():
            val = self.get(name)
            if val:
                masked = val[:6] + ("*" * 12)
                table.add_row(
                    name.capitalize(),
                    "[bold green]✓ Active[/bold green]",
                    f"[green]{masked}[/green]",
                    ""
                )
            else:
                if suppress:
                    table.add_row(
                        name.capitalize(),
                        "[dim]– Suppressed[/dim]",
                        "",
                        ""
                    )
                else:
                    table.add_row(
                        name.capitalize(),
                        "[red]✗ Not set[/red]",
                        "",
                        signup
                    )

        console.print(table)

        active = self.active_count()
        console.print(f"  [bold]{active} / {len(PROVIDERS)} API keys active.[/bold]")

        if active < len(PROVIDERS) and not suppress:
            console.print(
                f"  [yellow]Tip:[/yellow] Add keys to [cyan]{CONFIG_PATH}[/cyan] or export as env vars.\n"
                f"  [yellow]Tip:[/yellow] Suppress these notices with [bold]--no-api-warnings[/bold]"
            )
        console.print()