"""
modules/github_dork.py — GitHub Code Search dorking

Searches GitHub's code index for sensitive information related to the target:
hardcoded secrets, config files, .env exposure, internal endpoints, and more.

Requires a GitHub personal access token for the code search API.
Without a token: 10 requests/minute. With token: 30 requests/minute.

Add to ~/.config/sayad/config.yaml:
  github_token: "ghp_your_token_here"
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


# ── Dork definitions ──────────────────────────────────────────
# Each entry: (query_template, display_category, severity)
# {domain} is replaced with the actual target domain at runtime.

DORKS = [
    # Secrets / credentials
    ('"{domain}" password',              "Password",          "high"),
    ('"{domain}" api_key',               "API Key",           "high"),
    ('"{domain}" secret',                "Secret",            "high"),
    ('"{domain}" token',                 "Token",             "high"),
    ('"{domain}" private_key',           "Private Key",       "critical"),
    ('"{domain}" aws_access_key_id',     "AWS Access Key",    "critical"),
    ('"{domain}" aws_secret_access_key', "AWS Secret Key",    "critical"),
    ('"{domain}" client_secret',         "OAuth Secret",      "high"),
    ('"{domain}" bearer',                "Bearer Token",      "high"),
    # Config file exposure
    ('filename:.env "{domain}"',         ".env File",         "critical"),
    ('filename:*.env "{domain}"',        ".env (wildcard)",   "critical"),
    ('filename:config.json "{domain}"',  "Config JSON",       "high"),
    ('filename:settings.py "{domain}"',  "Django Settings",   "medium"),
    ('filename:*.yml "{domain}" password', "YAML Secret",     "high"),
    ('filename:docker-compose.yml "{domain}"', "Docker Compose", "medium"),
    # Database / connection strings
    ('"{domain}" db_password',           "DB Password",       "critical"),
    ('"{domain}" jdbc:{domain}',         "JDBC URL",          "medium"),
    ('"{domain}" mongodb+srv',           "MongoDB URI",       "high"),
    ('"{domain}" redis://',              "Redis URI",         "high"),
    # Infrastructure hints
    ('"{domain}" internal',              "Internal Ref",      "low"),
    ('"{domain}" staging',              "Staging Ref",       "low"),
    ('"{domain}" Authorization:',        "Auth Header",       "medium"),
    ('"{domain}" X-API-Key',             "API Header",        "medium"),
]

SEVERITY_COLOUR = {
    "critical": "[bold red]critical[/bold red]",
    "high":     "[red]high[/red]",
    "medium":   "[yellow]medium[/yellow]",
    "low":      "[dim]low[/dim]",
}


# ── GitHub API helper ─────────────────────────────────────────

def _gh_search(
    query: str,
    token: Optional[str],
    max_results: int = 10,
) -> Optional[list]:
    """
    Call GitHub code search API.

    Returns list of result dicts, empty list if nothing found,
    or None if rate-limited (caller should stop).
    """
    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/code?q={encoded}&per_page={min(max_results, 30)}"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SayadRecon/2.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return [
                {
                    "repo":     item.get("repository", {}).get("full_name", ""),
                    "path":     item.get("path", ""),
                    "url":      item.get("html_url", ""),
                    "query":    query,
                }
                for item in data.get("items", [])
            ]

    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            # Check Retry-After or treat as rate limit
            return None
        if e.code == 422:
            return []   # bad query syntax, skip silently
        if e.code == 401:
            return []   # bad token — caller will see 0 results
        return []
    except (urllib.error.URLError, OSError):
        return []


# ── Main phase function ───────────────────────────────────────

def run_github_dorking(
    domain: str,
    out: Path,
    config,
    console,
) -> int:
    """
    Run all GitHub dorks for the target domain.

    Writes results to <out>/github_dorks/{findings.txt,findings.json}.
    Returns total unique repository count.
    """
    from rich.rule import Rule
    from rich.table import Table

    console.print(Rule("[bold cyan]PHASE — GitHub Dorking[/bold cyan]"))

    token: Optional[str] = getattr(config, "github_token", None)

    if token:
        console.print("[green][+][/green] GitHub token active — authenticated code search")
        delay = 2.5   # ~24 req/min, safely under 30
    else:
        console.print(
            "[yellow][!][/yellow] No GitHub token — unauthenticated (10 req/min).\n"
            f"    Add [bold]github_token[/bold] to [cyan]~/.config/sayad/config.yaml[/cyan]"
        )
        delay = 7.0   # ~8 req/min, safely under 10

    dork_dir = out / "github_dorks"
    dork_dir.mkdir(exist_ok=True)

    table = Table(
        title="GitHub Dork Results",
        border_style="dim",
        title_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Category",    style="cyan", width=22)
    table.add_column("Severity",    width=14)
    table.add_column("Results",     justify="right", width=8)
    table.add_column("Top Repo",    style="dim")

    all_findings: list = []
    seen_repos:   set  = set()
    rate_limited = False

    for query_tmpl, category, severity in DORKS:
        if rate_limited:
            break

        query   = query_tmpl.replace("{domain}", domain)
        results = _gh_search(query, token, max_results=10)

        time.sleep(delay)

        if results is None:
            rate_limited = True
            console.print(
                "[yellow][!][/yellow] GitHub rate limit hit — stopping dorks early. "
                "Add a token for higher limits."
            )
            break

        new_in_query = 0
        top_repo = "—"
        for r in results:
            r["category"] = category
            r["severity"] = severity
            if r["repo"] not in seen_repos:
                seen_repos.add(r["repo"])
                all_findings.append(r)
                new_in_query += 1
            if top_repo == "—" and r["repo"]:
                top_repo = r["repo"]

        count_str = (
            f"[bold red]{len(results)}[/bold red]"
            if len(results) > 0 and severity in ("critical", "high")
            else (f"[bold]{len(results)}[/bold]" if len(results) > 0 else "[dim]0[/dim]")
        )
        table.add_row(category, SEVERITY_COLOUR.get(severity, severity), count_str, top_repo)

    console.print(table)

    if all_findings:
        # ── Text report ───────────────────────────────────────
        text_lines = [f"# GitHub Dork Findings — {domain}\n"]
        for f in all_findings:
            text_lines.append(
                f"[{f['severity'].upper()}] [{f['category']}] "
                f"{f['repo']}/{f['path']}"
            )
            text_lines.append(f"  URL:   {f['url']}")
            text_lines.append(f"  Query: {f['query']}")
            text_lines.append("")
        (dork_dir / "findings.txt").write_text("\n".join(text_lines))

        # ── JSON report ───────────────────────────────────────
        (dork_dir / "findings.json").write_text(json.dumps(all_findings, indent=2))

        crit_count = sum(1 for f in all_findings if f["severity"] == "critical")
        high_count = sum(1 for f in all_findings if f["severity"] == "high")

        console.print(
            f"[green][+][/green] GitHub exposure: [bold]{len(all_findings)}[/bold] unique repos"
        )
        if crit_count or high_count:
            console.print(
                f"[red][!][/red] "
                f"[bold red]{crit_count} critical[/bold red] / "
                f"[red]{high_count} high[/red] severity dork hits"
            )
        console.print(f"[green][+][/green] Results → [cyan]{dork_dir}[/cyan]")
    else:
        console.print("[dim]  No GitHub code exposure found.[/dim]")
        (dork_dir / "findings.txt").write_text("")

    return len(all_findings)
