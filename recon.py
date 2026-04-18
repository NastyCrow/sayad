#!/usr/bin/env python3
"""
╔═══════════════════════════════════════╗
║   Sayad Recon Framework — Python     ║
║   Bug Bounty Reconnaissance Pipeline  ║
╚═══════════════════════════════════════╝
"""

import argparse
import asyncio
import os
import re
import signal
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ── Fix: ensure modules/ is always importable regardless of invocation context ──
sys.path.insert(0, str(Path(__file__).resolve().parent))

# ── Dependency check ──────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.rule import Rule
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    import aiohttp
    import yaml
except ImportError:
    print("\n[!] Missing dependencies. Run:\n")
    print("    pip install rich aiohttp pyyaml\n")
    sys.exit(1)

from modules.config import Config
from modules.checkpoint import CheckpointManager, CheckpointError
from modules.subdomains import enumerate_subdomains
from modules.scope import ScopeManager

# ── Global state (needed by signal handler) ───────────────────
console = Console()
_checkpoint: CheckpointManager = None
_domain: str = ""
_out: Path = None


# ─────────────────────────────────────────────────────────────
# Signal Handler — Ctrl+C saves checkpoint and exits cleanly
# ─────────────────────────────────────────────────────────────
def _handle_interrupt(signum, frame):
    console.print()
    console.print(Rule("[yellow]Interrupted[/yellow]"))
    if _checkpoint and _checkpoint.has_progress():
        _checkpoint.save()
        console.print(f"[yellow][!][/yellow] Checkpoint saved → [cyan]{_checkpoint.path}[/cyan]")
        console.print(f"[green][+][/green] Resume with:")
        console.print(f"    [bold]python3 recon.py -d {_domain} --resume[/bold]\n")
    else:
        console.print("[yellow][!][/yellow] No progress to save.")
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_interrupt)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def validate_domain(domain: str) -> tuple:
    """Returns (is_valid: bool, error_msg: str)."""
    domain = domain.strip()
    if not domain:
        return False, "Domain cannot be empty"
    if domain.startswith(("http://", "https://")):
        return False, "Provide the domain only (e.g. example.com), not a full URL"
    # Shell-injection guard
    if any(c in domain for c in (' ', ';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\r')):
        return False, f"Domain contains invalid characters"
    if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
        return False, f"'{domain}' does not look like a valid domain name"
    return True, ""


def run_tool(cmd: list, out_file: Path = None, timeout: int = 300) -> str:
    """Run an external tool, write stdout to file if given. Returns stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip()
        if out_file and output:
            out_file.write_text(output)
        # Log stderr if tool produced warnings/errors (non-empty, non-whitespace)
        if result.stderr and result.stderr.strip():
            stderr_preview = result.stderr.strip().splitlines()[0][:120]
            console.print(f"[dim]  [{cmd[0]}] stderr: {stderr_preview}[/dim]")
        return output
    except FileNotFoundError:
        console.print(f"[yellow][!][/yellow] Tool not found: [bold]{cmd[0]}[/bold] — skipping.")
        return ""
    except subprocess.TimeoutExpired:
        console.print(f"[yellow][!][/yellow] {cmd[0]} timed out after {timeout}s — skipping.")
        return ""
    except Exception as e:
        console.print(f"[yellow][!][/yellow] {cmd[0]} error: {e}")
        return ""


def count_lines(path: Path) -> int:
    try:
        return sum(1 for l in path.read_text(errors="ignore").splitlines() if l.strip())
    except Exception:
        return 0


def banner():
    console.print()
    console.print(Panel(
        Text.assemble(
            ("  ____    _    __   __   __   _    ____\n", "bold magenta"),
            (" / ___|  / \\   \\ \\ / /  \\ \\ / /  / _  |\n", "bold magenta"),
            (" \\___ \\ / _ \\   \\ V /    \\ V /  | |_| |\n", "bold magenta"),
            ("  ___) / ___ \\   | |      | |    \\__  |\n", "bold magenta"),
            (" |____/_/   \\_\\  |_|      |_|      |_/\n", "bold magenta"),
            ("   RECON FRAMEWORK — Python Edition", "bold cyan"),
        ),
        border_style="magenta",
        padding=(0, 2),
    ))
    console.print()


# ─────────────────────────────────────────────────────────────
# Scope Safety Confirmation
# ─────────────────────────────────────────────────────────────

def scope_safety_prompt(domain: str, scan_scope: str, auto_yes: bool = False) -> bool:
    """
    Display a legal authorization warning and require explicit confirmation
    before any active scanning begins.

    Returns False if the user declines (caller should abort).
    Use auto_yes=True (--yes flag) for non-interactive / CI contexts.
    """
    if auto_yes:
        return True

    console.print()
    console.print(Panel(
        Text.assemble(
            ("  ⚠  AUTHORIZATION REQUIRED\n\n", "bold yellow"),
            ("  You are about to run active reconnaissance against:\n\n", "white"),
            (f"  Target : {domain}\n", "bold cyan"),
            (f"  Scope  : {scan_scope}\n\n", "bold yellow"),
            ("  Unauthorized scanning is ", "white"),
            ("illegal", "bold red"),
            (" in most jurisdictions\n", "white"),
            ("  and violates most bug bounty programme terms.\n\n", "white"),
            ("  By proceeding you confirm that you hold ", "white"),
            ("explicit written\n  authorization", "bold green"),
            (" to test this target.", "white"),
        ),
        border_style="yellow",
        title="[bold yellow]Legal Notice[/bold yellow]",
        padding=(0, 2),
    ))

    confirmed = Confirm.ask(
        f"\n  I have authorization to scan [bold cyan]{domain}[/bold cyan]",
        default=False,
    )

    if not confirmed:
        console.print("\n[yellow][!][/yellow] Scan cancelled. No targets were contacted.\n")
        return False

    return True


# ─────────────────────────────────────────────────────────────
# Phase 2 — DNS Resolution & Live Host Probing
# ─────────────────────────────────────────────────────────────

def phase_probing(out: Path, threads: int) -> list:
    console.print(Rule("[bold cyan]PHASE 2 — DNS Resolution & Live Host Probing[/bold cyan]"))

    all_subs  = out / "subdomains" / "all_subdomains.txt"
    resolved  = out / "hosts" / "resolved.txt"
    live_urls = out / "hosts" / "live_urls.txt"
    live_json = out / "hosts" / "live_hosts.json"

    if not all_subs.exists() or count_lines(all_subs) == 0:
        console.print("[yellow][!][/yellow] No subdomains found — skipping probing.")
        return []

    with console.status("[cyan]Resolving DNS with dnsx...[/cyan]"):
        run_tool(
            ["dnsx", "-l", str(all_subs), "-silent", "-o", str(resolved), "-t", str(threads)],
            timeout=300,
        )
    if resolved.exists():
        console.print(f"[green][+][/green] DNS resolved: [bold]{count_lines(resolved)}[/bold] hosts")

    with console.status("[cyan]Probing live HTTP hosts with httpx...[/cyan]"):
        run_tool([
            "httpx", "-l", str(all_subs),
            "-silent", "-title", "-status-code", "-tech-detect",
            "-content-length", "-ip",
            "-threads", str(threads),
            "-o", str(live_urls),
            "-json", "-output", str(live_json),
        ], timeout=400)

    if live_urls.exists():
        live = [l for l in live_urls.read_text().splitlines() if l.strip()]
        console.print(f"[green][+][/green] Live HTTP hosts: [bold]{len(live)}[/bold]")
        return live
    return []


# ─────────────────────────────────────────────────────────────
# Phase 3 — Port Scanning + XML parsing
# ─────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_path: Path):
    """Parse nmap XML and display a Rich table of open ports."""
    if not xml_path.exists():
        return

    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
    except ET.ParseError as exc:
        console.print(f"[yellow][!][/yellow] Could not parse nmap XML: {exc}")
        return

    table = Table(
        title="Open Ports Summary",
        border_style="dim",
        title_style="bold",
        show_lines=False,
    )
    table.add_column("Host",     style="cyan", width=32)
    table.add_column("Port",     justify="right", width=10)
    table.add_column("Service",  width=16)
    table.add_column("Version",  style="dim")

    total_open = 0
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip      = addr_el.get("addr", "?") if addr_el is not None else "?"
        hn_el   = host.find(".//hostname")
        name    = hn_el.get("name", ip) if hn_el is not None else ip
        display = f"{name} ({ip})" if name != ip else ip

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        first = True
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid   = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            svc_el   = port.find("service")
            svc_name = svc_el.get("name", "?") if svc_el is not None else "?"
            svc_ver  = ""
            if svc_el is not None:
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
                svc_ver = f"{product} {version}".strip()

            table.add_row(
                display if first else "",
                f"{portid}/{protocol}",
                svc_name,
                svc_ver,
            )
            first = False
            total_open += 1

    if total_open:
        console.print(table)
        console.print(f"[green][+][/green] Open ports found: [bold]{total_open}[/bold]")
    else:
        console.print("[dim]  No open ports in nmap output.[/dim]")


def phase_portscan(out: Path, deep: bool):
    console.print(Rule("[bold cyan]PHASE 3 — Port Scanning[/bold cyan]"))

    resolved  = out / "hosts" / "resolved.txt"
    ips_file  = out / "ports" / "target_ips.txt"
    nmap_base = str(out / "ports" / "nmap_scan")

    if not resolved.exists():
        console.print("[yellow][!][/yellow] No resolved hosts — skipping port scan.")
        return

    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = set()
    for line in resolved.read_text().splitlines():
        for ip in ip_pattern.findall(line):
            ips.add(ip)

    if not ips:
        console.print("[yellow][!][/yellow] No IPs extracted — skipping port scan.")
        return

    ips_file.write_text("\n".join(sorted(ips)))
    console.print(f"[green][+][/green] Scanning [bold]{len(ips)}[/bold] unique IPs")

    top_ports = "5000" if deep else "1000"
    with console.status(f"[cyan]Running Nmap (top {top_ports} ports)...[/cyan]"):
        run_tool([
            "nmap", "-iL", str(ips_file),
            "--top-ports", top_ports,
            "-sV", "--script=banner,http-title,ssl-cert",
            "-T4", "--open",
            "-oA", nmap_base,
        ], timeout=600)

    console.print(f"[green][+][/green] Port scan complete → {nmap_base}.*")
    _parse_nmap_xml(Path(nmap_base + ".xml"))


# ─────────────────────────────────────────────────────────────
# Phase 4 — URL & Endpoint Discovery
# ─────────────────────────────────────────────────────────────

def phase_crawl(out: Path, scope_targets: list, threads: int):
    console.print(Rule("[bold cyan]PHASE 4 — URL & Endpoint Discovery[/bold cyan]"))

    urls_dir   = out / "urls"
    scope_file = out / "scope_targets.txt"
    scope_file.write_text("\n".join(scope_targets))

    console.print(f"[green][+][/green] Crawling [bold]{len(scope_targets)}[/bold] scoped target(s)")

    # GAU
    with console.status("[cyan]Running GAU (historical URLs)...[/cyan]"):
        gau_out = urls_dir / "gau.txt"
        run_tool([
            "gau", "--threads", str(threads),
            "--blacklist", "png,jpg,gif,svg,ico,css,woff,ttf",
            "--o", str(gau_out),
        ] + scope_targets, timeout=300)
        if gau_out.exists():
            console.print(f"[green][+][/green] GAU: [bold]{count_lines(gau_out)}[/bold] URLs")

    # Waybackurls
    with console.status("[cyan]Running Waybackurls...[/cyan]"):
        wb_out = urls_dir / "wayback.txt"
        for target in scope_targets:
            out_lines = run_tool(["waybackurls", target], timeout=120)
            with open(wb_out, "a") as f:
                f.write(out_lines + "\n")
        if wb_out.exists():
            console.print(f"[green][+][/green] Waybackurls: [bold]{count_lines(wb_out)}[/bold] URLs")

    # Katana
    with console.status("[cyan]Running Katana (active crawl)...[/cyan]"):
        katana_out = urls_dir / "katana.txt"
        run_tool([
            "katana", "-list", str(scope_file),
            "-silent", "-d", "3", "-jc", "-kf", "all",
            "-c", str(threads),
            "-o", str(katana_out),
        ], timeout=400)
        if katana_out.exists():
            console.print(f"[green][+][/green] Katana: [bold]{count_lines(katana_out)}[/bold] endpoints")

    # Merge and deduplicate
    all_urls = set()
    for f in urls_dir.glob("*.txt"):
        try:
            all_urls.update(l for l in f.read_text(errors="ignore").splitlines() if l.startswith("http"))
        except Exception:
            pass

    all_urls_file = urls_dir / "all_urls.txt"
    all_urls_file.write_text("\n".join(sorted(all_urls)))
    console.print(f"[green][+][/green] Total unique URLs: [bold]{len(all_urls)}[/bold]")

    # Interesting endpoints (broader pattern, deduplicated)
    keywords = r"(api|admin|auth|login|upload|dashboard|graphql|swagger|debug|config|backup|\.json|\.xml|\.env|\.git|internal|secret|token|key|reset|password|register|oauth|webhook)"
    interesting = sorted({u for u in all_urls if re.search(keywords, u, re.I)})
    (urls_dir / "interesting_endpoints.txt").write_text("\n".join(interesting))
    console.print(f"[green][+][/green] Interesting endpoints: [bold]{len(interesting)}[/bold]")

    # JS files
    js_files = [u for u in all_urls if re.search(r"\.js(\?|$)", u)]
    (out / "js" / "js_files.txt").write_text("\n".join(js_files))
    console.print(f"[green][+][/green] JS files found: [bold]{len(js_files)}[/bold]")

    return list(all_urls)


# ─────────────────────────────────────────────────────────────
# Phase 5 — Parameter Discovery (parallelised)
# ─────────────────────────────────────────────────────────────

def phase_params(out: Path, scope_targets: list):
    console.print(Rule("[bold cyan]PHASE 5 — Parameter Discovery[/bold cyan]"))
    console.print(f"[green][+][/green] Running param discovery on [bold]{len(scope_targets)}[/bold] target(s)")

    import hashlib
    params_dir = out / "params"

    def _run_paramspider(target: str):
        hostname = target.split("://")[-1].split("/")[0]
        tag      = hashlib.md5(target.encode()).hexdigest()[:8]
        out_file = params_dir / f"paramspider_{tag}.txt"
        run_tool(
            ["paramspider", "-d", hostname, "-o", str(out_file)],
            timeout=120,
        )

    # Parallel ParamSpider — up to 5 concurrent processes
    workers = min(5, len(scope_targets))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_run_paramspider, t): t for t in scope_targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                future.result()
            except Exception as exc:
                console.print(f"[yellow][!][/yellow] ParamSpider error for {target}: {exc}")

    # Extract params from crawled URLs
    all_urls_file = out / "urls" / "all_urls.txt"
    if all_urls_file.exists():
        params = set()
        for url in all_urls_file.read_text(errors="ignore").splitlines():
            if "?" in url:
                qs = url.split("?", 1)[1]
                for pair in qs.split("&"):
                    p = pair.split("=")[0].strip()
                    if p:
                        params.add(p)
        (params_dir / "discovered_params.txt").write_text("\n".join(sorted(params)))
        console.print(f"[green][+][/green] Unique parameters discovered: [bold]{len(params)}[/bold]")


# ─────────────────────────────────────────────────────────────
# Phase 6 — Nuclei Vulnerability Scanning
# ─────────────────────────────────────────────────────────────

def phase_nuclei(out: Path, scope_targets: list, severity: str, threads: int, notifier=None, domain: str = ""):
    console.print(Rule("[bold cyan]PHASE 6 — Nuclei Vulnerability Scanning[/bold cyan]"))

    live_urls  = out / "hosts" / "live_urls.txt"
    nuclei_dir = out / "nuclei"

    if live_urls.exists() and scope_targets:
        scoped_live = [
            u for u in live_urls.read_text().splitlines()
            if any(t in u for t in scope_targets)
        ]
    else:
        scoped_live = []

    if not scoped_live:
        console.print("[yellow][!][/yellow] No live scoped hosts for Nuclei — skipping.")
        return

    scoped_file = nuclei_dir / "scoped_live.txt"
    scoped_file.write_text("\n".join(scoped_live))
    console.print(f"[green][+][/green] Scanning [bold]{len(scoped_live)}[/bold] scoped hosts")

    with console.status("[cyan]Updating Nuclei templates...[/cyan]"):
        run_tool(["nuclei", "-update-templates", "-silent"], timeout=120)

    findings      = nuclei_dir / "findings.txt"
    findings_json = nuclei_dir / "findings.json"

    with console.status(f"[cyan]Running Nuclei (severity: {severity})...[/cyan]"):
        run_tool([
            "nuclei", "-l", str(scoped_file),
            "-severity", severity,
            "-c", str(threads),
            "-o", str(findings),
            "-json-export", str(findings_json),
            "-silent",
        ], timeout=900)

    if findings.exists():
        hits  = count_lines(findings)
        crits = [
            l for l in findings.read_text(errors="ignore").splitlines()
            if re.search(r'\[(critical|high)\]', l, re.I)
        ]
        (nuclei_dir / "critical_high.txt").write_text("\n".join(crits))
        console.print(f"[green][+][/green] Nuclei findings: [bold]{hits}[/bold]")
        if crits:
            console.print(f"[red][!][/red] Critical/High: [bold red]{len(crits)}[/bold red]")
            # Notify immediately on critical/high
            if notifier and crits:
                notifier.critical_found(domain, crits[0])


# ─────────────────────────────────────────────────────────────
# Phase 7 — JS Secret Analysis (uses consolidated patterns)
# ─────────────────────────────────────────────────────────────

def phase_js(out: Path):
    console.print(Rule("[bold cyan]PHASE 7 — JS & Secret Analysis[/bold cyan]"))
    import urllib.request
    import hashlib

    js_dir       = out / "js"
    js_files_list = js_dir / "js_files.txt"

    if not js_files_list.exists() or count_lines(js_files_list) == 0:
        console.print("[yellow][!][/yellow] No JS files found — skipping.")
        return

    files_dir = js_dir / "files"
    files_dir.mkdir(exist_ok=True)

    js_urls = [l for l in js_files_list.read_text().splitlines() if l.strip()]
    console.print(f"[green][+][/green] Analysing [bold]{len(js_urls)}[/bold] JS files...")

    # Consolidated secret patterns (aligned with js_analysis.py)
    from js_analysis import SECRET_PATTERNS, ENDPOINT_PATTERN, SENSITIVE_PATTERN

    secrets: list  = []
    endpoints: set = set()
    sensitive: set = set()
    download_errors = 0

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                  TextColumn("{task.completed}/{task.total}"), console=console) as progress:
        task = progress.add_task("[cyan]Analysing JS files...", total=len(js_urls))

        for url in js_urls:
            fname = hashlib.md5(url.encode()).hexdigest()
            fpath = files_dir / f"{fname}.js"

            # Use cached version if available
            if not fpath.exists() or fpath.stat().st_size == 0:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        content = resp.read().decode("utf-8", errors="ignore")
                    if content.strip():
                        fpath.write_text(content)
                except Exception as exc:
                    download_errors += 1
                    console.print(f"[dim]  [JS] download failed {url.split('/')[-1]}: {type(exc).__name__}[/dim]")
                    progress.advance(task)
                    continue

            try:
                content = fpath.read_text(errors="ignore")
            except Exception:
                progress.advance(task)
                continue

            for pattern, label in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    val = match.group(1) if match.lastindex else match.group(0)
                    if len(val) > 6:
                        secrets.append(f"[{label}] {val[:60]}{'...' if len(val)>60 else ''}  (from: {url})")

            for match in ENDPOINT_PATTERN.finditer(content):
                endpoints.add(match.group(1))

            for match in SENSITIVE_PATTERN.finditer(content):
                sensitive.add(match.group(1))

            progress.advance(task)

    if download_errors:
        console.print(f"[yellow][!][/yellow] {download_errors} JS file(s) failed to download")

    (js_dir / "potential_secrets.txt").write_text("\n".join(sorted(set(secrets))))
    (js_dir / "js_endpoints.txt").write_text("\n".join(sorted(endpoints)))
    (js_dir / "js_sensitive_paths.txt").write_text("\n".join(sorted(sensitive)))
    console.print(f"[green][+][/green] Potential secrets: [bold]{len(set(secrets))}[/bold]")
    console.print(f"[green][+][/green] JS endpoints: [bold]{len(endpoints)}[/bold]")
    console.print(f"[green][+][/green] Sensitive paths: [bold]{len(sensitive)}[/bold]")


# ─────────────────────────────────────────────────────────────
# Phase 8 — Report
# ─────────────────────────────────────────────────────────────

def phase_report(out: Path, domain: str, dork_hits: int = 0):
    console.print(Rule("[bold cyan]PHASE 8 — Generating Summary Report[/bold cyan]"))

    report = out / "reports" / "summary.md"
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def c(f):
        return str(count_lines(out / f)) if (out / f).exists() else "0"

    content = f"""# Sayad Recon Report — {domain}
**Date:** {now}

---

## Statistics

| Phase | Result |
|-------|--------|
| Subdomains Discovered | {c("subdomains/all_subdomains.txt")} |
| Live HTTP Hosts | {c("hosts/live_urls.txt")} |
| Total URLs | {c("urls/all_urls.txt")} |
| Interesting Endpoints | {c("urls/interesting_endpoints.txt")} |
| JS Files | {c("js/js_files.txt")} |
| Potential Secrets | {c("js/potential_secrets.txt")} |
| JS Endpoints | {c("js/js_endpoints.txt")} |
| Parameters Discovered | {c("params/discovered_params.txt")} |
| Nuclei Findings | {c("nuclei/findings.txt")} |
| Critical/High | {c("nuclei/critical_high.txt")} |
| GitHub Dork Hits | {dork_hits} |

---

## Critical/High Findings
"""
    crit_file = out / "nuclei" / "critical_high.txt"
    content += crit_file.read_text(errors="ignore") if crit_file.exists() else "_None found._\n"

    content += "\n---\n## Potential Secrets in JS\n"
    sec_file = out / "js" / "potential_secrets.txt"
    if sec_file.exists():
        lines = sec_file.read_text(errors="ignore").splitlines()
        content += "\n".join(lines[:20])
        if len(lines) > 20:
            content += f"\n\n_...and {len(lines)-20} more (see full file)_"
    else:
        content += "_None found._\n"

    content += "\n---\n## Interesting Endpoints (top 30)\n"
    ep_file = out / "urls" / "interesting_endpoints.txt"
    if ep_file.exists():
        content += "\n".join(ep_file.read_text(errors="ignore").splitlines()[:30])
    else:
        content += "_None found._\n"

    if dork_hits:
        content += "\n---\n## GitHub Dork Hits\n"
        dork_file = out / "github_dorks" / "findings.txt"
        if dork_file.exists():
            content += "\n".join(dork_file.read_text(errors="ignore").splitlines()[:40])
        else:
            content += f"_{dork_hits} hits (see github_dorks/findings.txt)_\n"

    content += "\n\n---\n*Generated by Sayad Recon Framework*\n"
    report.write_text(content)
    console.print(f"[green][+][/green] Report saved → [cyan]{report}[/cyan]")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="sayad",
        description="Sayad Recon Framework — Bug Bounty Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -d hackerone.com
  python3 recon.py -d hackerone.com --deep
  python3 recon.py -d hackerone.com --scan-scope all
  python3 recon.py -d hackerone.com --scan-scope targets.txt
  python3 recon.py -d hackerone.com --resume
  python3 recon.py -d hackerone.com --github-dork
  python3 recon.py -d hackerone.com --yes          # skip auth prompt (CI/automated)
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default=str(Path.home() / "recon"), help="Output base directory")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("-s", "--severity", default="low,medium,high,critical", help="Nuclei severity filter")
    parser.add_argument("--deep", action="store_true", help="Deep mode: active Amass + full port scan")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument(
        "--scan-scope", default="main", metavar="SCOPE",
        help=(
            "Scope for deep scanning phases (crawl, params, nuclei).\n"
            "  main        — main domain only (default, safest)\n"
            "  all         — all discovered live subdomains\n"
            "  discovered  — interactively pick from discovered hosts\n"
            "  <file.txt>  — use a custom targets file"
        ),
    )
    parser.add_argument("--skip-nuclei",   action="store_true", help="Skip Nuclei scanning")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip Nmap port scan")
    parser.add_argument("--skip-crawl",    action="store_true", help="Skip URL crawling")
    parser.add_argument("--skip-js",       action="store_true", help="Skip JS analysis (run later with js_analyze.py)")
    parser.add_argument("--github-dork",   action="store_true", help="Run GitHub code search dorking phase")
    parser.add_argument("--no-api-warnings", action="store_true", help="Suppress missing API key warnings")
    parser.add_argument("--llm-analyze",   action="store_true", help="Feed scan output to local LLM (Ollama) after scan")
    parser.add_argument("--llm-model",     default="llama3",             metavar="MODEL", help="Ollama model (default: llama3)")
    parser.add_argument("--llm-url",       default="http://localhost:11434", metavar="URL", help="Ollama API URL")
    parser.add_argument("-y", "--yes",     action="store_true", help="Skip authorization confirmation prompt (use for CI/automated scans)")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    global _checkpoint, _domain, _out

    args   = parse_args()
    _domain = args.domain.strip()

    # ── Domain validation ─────────────────────────────────────
    valid, err = validate_domain(_domain)
    if not valid:
        console.print(f"[red][✗][/red] Invalid domain: {err}")
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────
    config = Config.load(suppress_warnings=args.no_api_warnings)
    Config.create_template()

    # ── Scope safety confirmation ──────────────────────────────
    if not scope_safety_prompt(_domain, args.scan_scope, auto_yes=args.yes):
        sys.exit(0)

    # ── Output directory ──────────────────────────────────────
    base = Path(args.output) / _domain
    base.mkdir(parents=True, exist_ok=True)

    # ── Checkpoint / resume ───────────────────────────────────
    chk_mgr   = CheckpointManager(base)
    _checkpoint = chk_mgr

    if args.resume:
        run_dir = chk_mgr.find_resumable()
        if run_dir:
            console.print(f"\n[green][+][/green] Resumable checkpoint: [cyan]{run_dir}[/cyan]")
            try:
                chk_mgr.load(run_dir)
            except CheckpointError as exc:
                console.print(f"[red][✗][/red] {exc}")
                sys.exit(1)
        else:
            console.print("[yellow][!][/yellow] No resumable checkpoint — starting fresh.")
            args.resume = False

    if not args.resume:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir   = base / timestamp
        for sub in ["subdomains","hosts","urls","ports","nuclei","js","params","osint","reports","github_dorks"]:
            (run_dir / sub).mkdir(parents=True, exist_ok=True)
        chk_mgr.init(run_dir, args)

    _out = run_dir

    # ── Notifier ──────────────────────────────────────────────
    from modules.notify import Notifier
    notifier = Notifier(
        slack_webhook=config.slack_webhook,
        discord_webhook=config.discord_webhook,
    )

    # ── Banner ────────────────────────────────────────────────
    banner()

    # ── Startup info table ────────────────────────────────────
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold")
    info.add_column()
    info.add_row("Target",     f"[bold cyan]{_domain}[/bold cyan]")
    info.add_row("Output",     str(run_dir))
    info.add_row("Scan Scope", f"[yellow]{args.scan_scope}[/yellow]")
    info.add_row("Deep Mode",  str(args.deep))
    info.add_row("Threads",    str(args.threads))
    info.add_row("GitHub Dork", "enabled" if args.github_dork else "disabled")
    info.add_row("Started",    datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(Panel(info, title="[bold]Run Configuration[/bold]", border_style="cyan"))
    console.print()

    # ── API key status ────────────────────────────────────────
    config.print_key_status(suppress=args.no_api_warnings)

    # ─────────────────────────────────────────────────────────
    # PHASE 1 — Subdomain Enumeration
    # ─────────────────────────────────────────────────────────
    if not chk_mgr.is_done("phase1"):
        console.print(Rule("[bold cyan]PHASE 1 — Subdomain Enumeration (14 Sources)[/bold cyan]"))
        subdomains = asyncio.run(enumerate_subdomains(_domain, run_dir, config))
        all_subs_file = run_dir / "subdomains" / "all_subdomains.txt"
        all_subs_file.write_text("\n".join(sorted(subdomains)))
        console.print(f"\n[green][+][/green] Total unique subdomains: [bold]{len(subdomains)}[/bold]")
        chk_mgr.complete("phase1", {"subdomains": list(subdomains)})
    else:
        console.print(Rule("[dim]PHASE 1 — Skipped (checkpoint)[/dim]"))
        subdomains = set(chk_mgr.get("phase1", "subdomains"))
        console.print(f"[green][+][/green] Loaded [bold]{len(subdomains)}[/bold] subdomains from checkpoint")

    # ─────────────────────────────────────────────────────────
    # PHASE 2 — DNS & Live Host Probing
    # ─────────────────────────────────────────────────────────
    if not chk_mgr.is_done("phase2"):
        live_hosts = phase_probing(run_dir, args.threads)
        chk_mgr.complete("phase2", {"live_hosts": live_hosts})
    else:
        console.print(Rule("[dim]PHASE 2 — Skipped (checkpoint)[/dim]"))
        live_hosts = chk_mgr.get("phase2", "live_hosts")
        console.print(f"[green][+][/green] Loaded [bold]{len(live_hosts)}[/bold] live hosts from checkpoint")

    # ─────────────────────────────────────────────────────────
    # PHASE 3 — Port Scanning
    # ─────────────────────────────────────────────────────────
    if not args.skip_portscan:
        if not chk_mgr.is_done("phase3"):
            phase_portscan(run_dir, args.deep)
            chk_mgr.complete("phase3", {})
        else:
            console.print(Rule("[dim]PHASE 3 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # Resolve scan scope
    # ─────────────────────────────────────────────────────────
    scope_mgr    = ScopeManager(_domain, live_hosts)
    scope_targets = scope_mgr.resolve(args.scan_scope, console)
    console.print(f"\n[bold]Scan scope resolved:[/bold] [yellow]{len(scope_targets)} target(s)[/yellow]")
    for t in scope_targets[:10]:
        console.print(f"  [cyan]→[/cyan] {t}")
    if len(scope_targets) > 10:
        console.print(f"  [dim]... and {len(scope_targets) - 10} more[/dim]")
    console.print()

    # ─────────────────────────────────────────────────────────
    # PHASE 4 — URL & Endpoint Discovery
    # ─────────────────────────────────────────────────────────
    if not args.skip_crawl:
        if not chk_mgr.is_done("phase4"):
            all_urls = phase_crawl(run_dir, scope_targets, args.threads)
            chk_mgr.complete("phase4", {"url_count": len(all_urls)})
        else:
            console.print(Rule("[dim]PHASE 4 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE 5 — Parameter Discovery
    # ─────────────────────────────────────────────────────────
    if not chk_mgr.is_done("phase5"):
        phase_params(run_dir, scope_targets)
        chk_mgr.complete("phase5", {})
    else:
        console.print(Rule("[dim]PHASE 5 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE 6 — Nuclei
    # ─────────────────────────────────────────────────────────
    if not args.skip_nuclei:
        if not chk_mgr.is_done("phase6"):
            phase_nuclei(run_dir, scope_targets, args.severity, args.threads,
                         notifier=notifier, domain=_domain)
            chk_mgr.complete("phase6", {})
        else:
            console.print(Rule("[dim]PHASE 6 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE 7 — JS Analysis
    # ─────────────────────────────────────────────────────────
    if args.skip_js:
        console.print(Rule("[dim]PHASE 7 — Skipped (--skip-js)[/dim]"))
        console.print(f"[yellow][!][/yellow] Run JS analysis later:")
        console.print(f"    [bold cyan]python3 js_analyze.py --scan-dir {run_dir}[/bold cyan]\n")
    elif not chk_mgr.is_done("phase7"):
        phase_js(run_dir)
        chk_mgr.complete("phase7", {})
    else:
        console.print(Rule("[dim]PHASE 7 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE 8 — GitHub Dorking (optional, --github-dork)
    # ─────────────────────────────────────────────────────────
    dork_hits = 0
    if args.github_dork:
        if not chk_mgr.is_done("phase_github"):
            from modules.github_dork import run_github_dorking
            dork_hits = run_github_dorking(_domain, run_dir, config, console)
            chk_mgr.complete("phase_github", {"dork_hits": dork_hits})
        else:
            console.print(Rule("[dim]PHASE — GitHub Dorking — Skipped (checkpoint)[/dim]"))
            dork_hits = chk_mgr.get("phase_github", "dork_hits") or 0
    else:
        console.print(Rule("[dim]PHASE — GitHub Dorking — Skipped (use --github-dork to enable)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE — Summary Report
    # ─────────────────────────────────────────────────────────
    phase_report(run_dir, _domain, dork_hits=dork_hits)
    chk_mgr.mark_complete()

    # ─────────────────────────────────────────────────────────
    # PHASE — Diff Report
    # ─────────────────────────────────────────────────────────
    from modules.diff import generate_diff
    diff_path = generate_diff(run_dir, _domain, console)
    if diff_path:
        console.print(f"[green][+][/green] Diff report → [cyan]{diff_path}[/cyan]")

    # ─────────────────────────────────────────────────────────
    # PHASE — LLM Analysis (optional)
    # ─────────────────────────────────────────────────────────
    if args.llm_analyze:
        from modules.llm import LLMAnalyzer
        analyzer = LLMAnalyzer(model=args.llm_model, base_url=args.llm_url, console=console)
        analyzer.run(run_dir, _domain)

    # ─────────────────────────────────────────────────────────
    # Final summary + notification
    # ─────────────────────────────────────────────────────────
    n_subs     = count_lines(run_dir / "subdomains" / "all_subdomains.txt")
    n_live     = count_lines(run_dir / "hosts"      / "live_urls.txt")
    n_findings = count_lines(run_dir / "nuclei"     / "findings.txt")
    n_crit     = count_lines(run_dir / "nuclei"     / "critical_high.txt")
    n_secrets  = count_lines(run_dir / "js"         / "potential_secrets.txt")

    console.print()
    console.print(Panel(
        f"[bold green]✅  RECON COMPLETE[/bold green]\n\n"
        f"  Domain     : [bold]{_domain}[/bold]\n"
        f"  Subdomains : [bold]{n_subs}[/bold]\n"
        f"  Live Hosts : [bold]{n_live}[/bold]\n"
        f"  Findings   : [bold red]{n_findings}[/bold red] "
        f"([red]{n_crit} Crit/High[/red])\n"
        f"  Secrets    : [bold yellow]{n_secrets}[/bold yellow] potential\n"
        + (f"  GitHub Hits: [bold]{dork_hits}[/bold] repos\n" if dork_hits else "")
        + (f"  Diff       : [cyan]{diff_path.name}[/cyan]\n" if diff_path else "")
        + f"\n  Output     : [cyan]{run_dir}[/cyan]\n"
        f"  Report     : [cyan]{run_dir / 'reports' / 'summary.md'}[/cyan]",
        border_style="green",
    ))

    notifier.scan_complete(_domain, {
        "subdomains":    n_subs,
        "live_hosts":    n_live,
        "findings":      n_findings,
        "critical_high": n_crit,
        "dork_hits":     dork_hits,
    })


if __name__ == "__main__":
    main()
