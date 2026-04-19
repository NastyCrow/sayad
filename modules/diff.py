"""
modules/diff.py — Diff reports between consecutive scan runs

Compares the current scan against the most recent completed run for the same
domain and produces an actionable Markdown change report.
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


def _fmt(prev: int, curr: int, bad_if_higher: bool = False) -> str:
    """Format a cell as 'prev → curr (±delta emoji)'."""
    delta = curr - prev
    if delta == 0:
        arrow = "—"
    elif delta > 0:
        arrow = f"+{delta} {'🔴' if bad_if_higher else '🟢'}"
    else:
        arrow = f"{delta} {'🟢' if bad_if_higher else '🟡'}"
    return f"{prev} → **{curr}** ({arrow})"


def _block(items: list, limit: int = 50) -> str:
    if not items:
        return "_None._\n"
    out = "\n".join(f"- `{item}`" for item in items[:limit])
    if len(items) > limit:
        out += f"\n\n_…and {len(items) - limit} more — see output files._"
    return out + "\n"


# ── Main entry point ──────────────────────────────────────────

def generate_diff(current_run: Path, domain: str, console=None) -> Optional[Path]:
    domain_dir = current_run.parent
    prev_run   = _find_previous_completed(domain_dir, current_run)

    if not prev_run:
        if console:
            console.print("[dim]  No previous completed run — diff skipped.[/dim]")
        return None

    # ── Load sets ─────────────────────────────────────────────
    c_subs  = _read_set(current_run / "subdomains" / "all_subdomains.txt")
    p_subs  = _read_set(prev_run    / "subdomains" / "all_subdomains.txt")
    c_hosts = _read_set(current_run / "hosts" / "live_urls.txt")
    p_hosts = _read_set(prev_run    / "hosts" / "live_urls.txt")
    c_find  = _read_set(current_run / "nuclei" / "findings.txt")
    p_find  = _read_set(prev_run    / "nuclei" / "findings.txt")
    c_crit  = _read_set(current_run / "nuclei" / "critical_high.txt")
    p_crit  = _read_set(prev_run    / "nuclei" / "critical_high.txt")
    c_sec   = _read_set(current_run / "js" / "potential_secrets.txt")
    p_sec   = _read_set(prev_run    / "js" / "potential_secrets.txt")
    c_ep    = _read_set(current_run / "urls" / "interesting_endpoints.txt")
    p_ep    = _read_set(prev_run    / "urls" / "interesting_endpoints.txt")
    c_dork  = _read_set(current_run / "github_dorks" / "findings.txt")
    p_dork  = _read_set(prev_run    / "github_dorks" / "findings.txt")

    # ── Diffs ─────────────────────────────────────────────────
    new_subs   = sorted(c_subs - p_subs)
    lost_subs  = sorted(p_subs - c_subs)
    new_hosts  = sorted(c_hosts - p_hosts)
    lost_hosts = sorted(p_hosts - c_hosts)
    new_find   = sorted(c_find - p_find)
    fixed_find = sorted(p_find - c_find)
    new_crit   = sorted(c_crit - p_crit)
    fixed_crit = sorted(p_crit - c_crit)
    new_sec    = sorted(c_sec - p_sec)
    new_ep     = sorted(c_ep - p_ep)
    new_dork   = sorted(c_dork - p_dork)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Priority triage ───────────────────────────────────────
    prios = []
    if new_crit:
        prios.append(f"1. 🚨 **{len(new_crit)} new Critical/High finding{'s' if len(new_crit)>1 else ''}** — validate and report immediately")
    if new_find:
        n = len(prios) + 1
        prios.append(f"{n}. 🔴 **{len(new_find)} new Nuclei finding{'s' if len(new_find)>1 else ''}** — triage by severity")
    if new_sec:
        n = len(prios) + 1
        prios.append(f"{n}. 🔑 **{len(new_sec)} new JS secret{'s' if len(new_sec)>1 else ''}** — validate and rotate if real")
    if new_dork:
        n = len(prios) + 1
        prios.append(f"{n}. 🐙 **{len(new_dork)} new GitHub exposure hit{'s' if len(new_dork)>1 else ''}** — check for credential leaks")
    if new_subs:
        n = len(prios) + 1
        prios.append(f"{n}. 📡 **{len(new_subs)} new subdomain{'s' if len(new_subs)>1 else ''}** — probe for exposed services and misconfigs")
    if new_hosts:
        n = len(prios) + 1
        prios.append(f"{n}. 🌐 **{len(new_hosts)} new live host{'s' if len(new_hosts)>1 else ''}** — run targeted vulnerability scan")
    if fixed_find:
        n = len(prios) + 1
        prios.append(f"{n}. ✅ **{len(fixed_find)} finding{'s' if len(fixed_find)>1 else ''} no longer detected** — verify remediation manually before closing")

    prio_block = "\n".join(prios) if prios else "_No significant changes since last scan._"

    # ── Report ────────────────────────────────────────────────
    sections = []

    # Header
    sections.append(f"""# 🔍 Diff Report — {domain}

| | |
|---|---|
| **Previous scan** | `{prev_run.name}` |
| **This scan** | `{current_run.name}` |
| **Generated** | {now} |

---

## 📊 Change Summary

| Metric | Change |
|--------|--------|
| Subdomains | {_fmt(len(p_subs), len(c_subs))} |
| Live Hosts | {_fmt(len(p_hosts), len(c_hosts))} |
| Nuclei Findings | {_fmt(len(p_find), len(c_find), bad_if_higher=True)} |
| Critical / High | {_fmt(len(p_crit), len(c_crit), bad_if_higher=True)} |
| JS Secrets | {_fmt(len(p_sec), len(c_sec), bad_if_higher=True)} |
| Interesting Endpoints | {_fmt(len(p_ep), len(c_ep))} |
| GitHub Dork Hits | {_fmt(len(p_dork), len(c_dork), bad_if_higher=True)} |

---

## 🎯 What to Look at First

{prio_block}

---""")

    # Critical/High — always first
    if new_crit:
        sections.append(f"""
## 🚨 New Critical / High Findings ({len(new_crit)})

> **Highest priority.** Validate, exploit, and write reports immediately.

{_block(new_crit, 60)}""")

    if fixed_crit:
        sections.append(f"""
## ✅ Resolved Critical / High ({len(fixed_crit)})

> No longer triggering. Verify manually — do not close without confirmation.

{_block(fixed_crit, 20)}""")

    if new_find:
        sections.append(f"""
## 🆕 New Nuclei Findings ({len(new_find)})

{_block(new_find, 100)}""")

    if fixed_find:
        sections.append(f"""
## ✅ Resolved Findings ({len(fixed_find)})

> Previously detected, now gone. Confirm fix before marking as remediated.

{_block(fixed_find, 40)}""")

    if new_sec:
        sections.append(f"""
## 🔑 New Potential Secrets ({len(new_sec)})

> Validate each — false positives are common but real hits are critical.

{_block(new_sec, 40)}""")

    if new_dork:
        sections.append(f"""
## 🐙 New GitHub Dork Hits ({len(new_dork)})

{_block(new_dork, 30)}""")

    if new_subs:
        sections.append(f"""
## 📡 New Subdomains ({len(new_subs)})

> New attack surface. Check for admin panels, dev environments, and misconfigs.

{_block(new_subs, 60)}""")

    if lost_subs:
        sections.append(f"""
## 📉 Lost Subdomains ({len(lost_subs)})

> No longer resolving — DNS changes, takedowns, or scope changes.

{_block(lost_subs, 30)}""")

    if new_hosts:
        sections.append(f"""
## 🌐 New Live Hosts ({len(new_hosts)})

{_block(new_hosts, 40)}""")

    if lost_hosts:
        sections.append(f"""
## 🔌 Hosts Gone Offline ({len(lost_hosts)})

{_block(lost_hosts, 20)}""")

    if new_ep:
        sections.append(f"""
## 🔗 New Interesting Endpoints ({len(new_ep)})

{_block(new_ep, 50)}""")

    total_new = len(new_crit) + len(new_find) + len(new_subs) + len(new_hosts) + len(new_sec) + len(new_dork)
    if total_new == 0 and not fixed_find:
        sections.append("\n## ℹ️ No Changes Detected\n\nAttack surface is stable since the previous scan.\n")

    sections.append("\n---\n*Generated by Sayad Recon Framework*\n")

    report = "\n".join(sections)
    report_path = current_run / "reports" / "diff_report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)
    return report_path
