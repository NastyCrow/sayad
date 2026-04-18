"""
modules/diff.py — Diff reports between consecutive scan runs

Compares the current scan against the most recent completed run for the same
domain and produces a Markdown report highlighting what's new, what resolved,
and what disappeared.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Helpers ───────────────────────────────────────────────────

def _read_set(path: Path) -> set:
    if not path.exists():
        return set()
    return {l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()}


def _find_previous_completed(domain_dir: Path, current_run: Path) -> Optional[Path]:
    """Return the most recent completed run directory that isn't current_run."""
    runs = sorted(
        [d for d in domain_dir.iterdir() if d.is_dir() and d != current_run],
        reverse=True,
    )
    for run in runs:
        cp = run / "checkpoint.json"
        if not cp.exists():
            continue
        try:
            state = json.loads(cp.read_text())
            if state.get("completed", False):
                return run
        except Exception:
            continue
    return None


def _section(lines: list, title: str, items: list, limit: int = 60):
    lines.append(f"\n## {title} ({len(items)})\n")
    if not items:
        lines.append("_None._\n")
        return
    for item in items[:limit]:
        lines.append(f"- `{item}`")
    if len(items) > limit:
        lines.append(f"\n_…and {len(items) - limit} more_")
    lines.append("")


# ── Main entry point ──────────────────────────────────────────

def generate_diff(current_run: Path, domain: str, console=None) -> Optional[Path]:
    """
    Compare current_run to the previous completed run for the same domain.

    Writes diff_report.md into current_run/reports/.
    Returns the report Path, or None if no previous run exists.
    """
    domain_dir = current_run.parent
    prev_run = _find_previous_completed(domain_dir, current_run)

    if not prev_run:
        if console:
            console.print("[dim]  No previous completed run — diff report skipped.[/dim]")
        return None

    # ── Load comparison sets ──────────────────────────────────
    curr_subs      = _read_set(current_run / "subdomains" / "all_subdomains.txt")
    prev_subs      = _read_set(prev_run    / "subdomains" / "all_subdomains.txt")

    curr_hosts     = _read_set(current_run / "hosts" / "live_urls.txt")
    prev_hosts     = _read_set(prev_run    / "hosts" / "live_urls.txt")

    curr_findings  = _read_set(current_run / "nuclei" / "findings.txt")
    prev_findings  = _read_set(prev_run    / "nuclei" / "findings.txt")

    curr_crit      = _read_set(current_run / "nuclei" / "critical_high.txt")
    prev_crit      = _read_set(prev_run    / "nuclei" / "critical_high.txt")

    curr_secrets   = _read_set(current_run / "js" / "potential_secrets.txt")
    prev_secrets   = _read_set(prev_run    / "js" / "potential_secrets.txt")

    curr_endpoints = _read_set(current_run / "urls" / "interesting_endpoints.txt")
    prev_endpoints = _read_set(prev_run    / "urls" / "interesting_endpoints.txt")

    curr_dorks     = _read_set(current_run / "github_dorks" / "findings.txt")
    prev_dorks     = _read_set(prev_run    / "github_dorks" / "findings.txt")

    # ── Compute diffs ─────────────────────────────────────────
    new_subs       = sorted(curr_subs      - prev_subs)
    gone_subs      = sorted(prev_subs      - curr_subs)
    new_hosts      = sorted(curr_hosts     - prev_hosts)
    gone_hosts     = sorted(prev_hosts     - curr_hosts)
    new_findings   = sorted(curr_findings  - prev_findings)
    fixed_findings = sorted(prev_findings  - curr_findings)
    new_crit       = sorted(curr_crit      - prev_crit)
    new_secrets    = sorted(curr_secrets   - prev_secrets)
    new_endpoints  = sorted(curr_endpoints - prev_endpoints)
    new_dorks      = sorted(curr_dorks     - prev_dorks)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Build report ──────────────────────────────────────────
    lines = [
        f"# Sayad Diff Report — {domain}",
        f"**Date:** {now}  ",
        f"**Current run:** `{current_run.name}`  ",
        f"**Previous run:** `{prev_run.name}`",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Category | New | Gone / Fixed |",
        "|----------|----:|-------------:|",
        f"| Subdomains            | {len(new_subs):>5} | {len(gone_subs):>12} |",
        f"| Live Hosts            | {len(new_hosts):>5} | {len(gone_hosts):>12} |",
        f"| Nuclei Findings       | {len(new_findings):>5} | {len(fixed_findings):>12} |",
        f"| Critical / High       | {len(new_crit):>5} | — |",
        f"| JS Secrets            | {len(new_secrets):>5} | — |",
        f"| Interesting Endpoints | {len(new_endpoints):>5} | — |",
        f"| GitHub Dork Hits      | {len(new_dorks):>5} | — |",
        "",
        "---",
    ]

    # ── New critical/high first (highest priority) ────────────
    if new_crit:
        lines.append("\n## \U0001f6a8 NEW Critical / High Findings\n")
        for item in new_crit:
            lines.append(f"- `{item}`")
        lines.append("")

    _section(lines, "New Nuclei Findings",       new_findings,   limit=100)
    _section(lines, "Resolved Findings",          fixed_findings, limit=50)
    _section(lines, "New Subdomains",             new_subs,       limit=60)
    _section(lines, "Lost Subdomains",            gone_subs,      limit=30)
    _section(lines, "New Live Hosts",             new_hosts,      limit=40)
    _section(lines, "Lost Live Hosts",            gone_hosts,     limit=20)
    _section(lines, "New JS Secrets",             new_secrets,    limit=40)
    _section(lines, "New Interesting Endpoints",  new_endpoints,  limit=50)
    _section(lines, "New GitHub Dork Hits",       new_dorks,      limit=30)

    lines.append("\n---\n*Generated by Sayad Recon Framework*\n")

    report_path = current_run / "reports" / "diff_report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines))

    return report_path
