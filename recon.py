#!/usr/bin/env python3
"""
╔═══════════════════════════════════════╗
║   Sayyad Recon Framework — Python     ║
║   Bug Bounty Reconnaissance Pipeline  ║
╚═══════════════════════════════════════╝
"""

import argparse
import asyncio
import os
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path

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
from modules.checkpoint import CheckpointManager
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
        console.print(f"[green][+][/green] Resume your scan with:")
        console.print(f"    [bold]python3 recon.py -d {_domain} --resume[/bold]\n")
    else:
        console.print("[yellow][!][/yellow] No progress to save.")
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_interrupt)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def run_tool(cmd: list, out_file: Path = None, timeout: int = 300) -> str:
    """Run an external tool, optionally writing stdout to file. Returns stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout.strip()
        if out_file and output:
            out_file.write_text(output)
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
        return sum(1 for _ in path.read_text().splitlines() if _)
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
        padding=(0, 2)
    ))
    console.print()


# ─────────────────────────────────────────────────────────────
# Phase 2 — DNS Resolution & Live Host Probing
# ─────────────────────────────────────────────────────────────
def phase_probing(out: Path, threads: int) -> list:
    console.print(Rule("[bold cyan]PHASE 2 — DNS Resolution & Live Host Probing[/bold cyan]"))

    all_subs = out / "subdomains" / "all_subdomains.txt"
    resolved = out / "hosts" / "resolved.txt"
    live_urls = out / "hosts" / "live_urls.txt"
    live_json = out / "hosts" / "live_hosts.json"

    if not all_subs.exists() or count_lines(all_subs) == 0:
        console.print("[yellow][!][/yellow] No subdomains found — skipping probing.")
        return []

    # dnsx — resolve DNS
    with console.status("[cyan]Resolving DNS with dnsx...[/cyan]"):
        run_tool(
            ["dnsx", "-l", str(all_subs), "-silent", "-o", str(resolved), "-t", str(threads)],
            timeout=300
        )
    if resolved.exists():
        console.print(f"[green][+][/green] DNS resolved: [bold]{count_lines(resolved)}[/bold] hosts")

    # httpx — probe HTTP
    with console.status("[cyan]Probing live HTTP hosts with httpx...[/cyan]"):
        run_tool([
            "httpx", "-l", str(all_subs),
            "-silent", "-title", "-status-code", "-tech-detect",
            "-content-length", "-ip",
            "-threads", str(threads),
            "-o", str(live_urls),
            "-json", "-output", str(live_json)
        ], timeout=400)

    if live_urls.exists():
        live = live_urls.read_text().splitlines()
        console.print(f"[green][+][/green] Live HTTP hosts: [bold]{len(live)}[/bold]")
        return live
    return []


# ─────────────────────────────────────────────────────────────
# Phase 3 — Port Scanning
# ─────────────────────────────────────────────────────────────
def phase_portscan(out: Path, deep: bool):
    console.print(Rule("[bold cyan]PHASE 3 — Port Scanning[/bold cyan]"))

    resolved = out / "hosts" / "resolved.txt"
    ips_file = out / "ports" / "target_ips.txt"

    if not resolved.exists():
        console.print("[yellow][!][/yellow] No resolved hosts — skipping port scan.")
        return

    # Extract IPs from resolved output
    import re
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

    ports = "--top-ports 5000" if deep else "--top-ports 1000"
    nmap_out = str(out / "ports" / "nmap_scan")

    with console.status(f"[cyan]Running Nmap ({ports.split()[1]} ports)...[/cyan]"):
        run_tool([
            "nmap", "-iL", str(ips_file),
            "--top-ports", "1000" if not deep else "5000",
            "-sV", "--script=banner,http-title,ssl-cert",
            "-T4", "--open",
            "-oA", nmap_out
        ], timeout=600)

    console.print(f"[green][+][/green] Port scan complete → {nmap_out}.*")


# ─────────────────────────────────────────────────────────────
# Phase 4 — URL & Endpoint Discovery
# ─────────────────────────────────────────────────────────────
def phase_crawl(out: Path, scope_targets: list, threads: int):
    console.print(Rule("[bold cyan]PHASE 4 — URL & Endpoint Discovery[/bold cyan]"))

    urls_dir = out / "urls"
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
            "-o", str(katana_out)
        ], timeout=400)
        if katana_out.exists():
            console.print(f"[green][+][/green] Katana: [bold]{count_lines(katana_out)}[/bold] endpoints")

    # Merge all URLs
    all_urls = set()
    for f in urls_dir.glob("*.txt"):
        try:
            all_urls.update(l for l in f.read_text().splitlines() if l.startswith("http"))
        except Exception:
            pass

    all_urls_file = urls_dir / "all_urls.txt"
    all_urls_file.write_text("\n".join(sorted(all_urls)))
    console.print(f"[green][+][/green] Total unique URLs: [bold]{len(all_urls)}[/bold]")

    # Extract interesting endpoints
    keywords = r"(api|admin|auth|login|upload|dashboard|graphql|swagger|debug|config|backup|\.json|\.xml|\.env|\.git)"
    import re
    interesting = [u for u in all_urls if re.search(keywords, u, re.I)]
    (urls_dir / "interesting_endpoints.txt").write_text("\n".join(interesting))
    console.print(f"[green][+][/green] Interesting endpoints: [bold]{len(interesting)}[/bold]")

    # Extract JS files
    js_files = [u for u in all_urls if re.search(r"\.js(\?|$)", u)]
    (out / "js" / "js_files.txt").write_text("\n".join(js_files))
    console.print(f"[green][+][/green] JS files found: [bold]{len(js_files)}[/bold]")

    return list(all_urls)


# ─────────────────────────────────────────────────────────────
# Phase 5 — Parameter Discovery
# ─────────────────────────────────────────────────────────────
def phase_params(out: Path, scope_targets: list):
    console.print(Rule("[bold cyan]PHASE 5 — Parameter Discovery[/bold cyan]"))
    console.print(f"[green][+][/green] Running param discovery on [bold]{len(scope_targets)}[/bold] target(s)")

    params_dir = out / "params"

    for target in scope_targets:
        with console.status(f"[cyan]ParamSpider → {target}[/cyan]"):
            run_tool(["paramspider", "-d", target, "-o", str(params_dir / f"paramspider_{target}.txt")], timeout=120)

    # Extract params from all discovered URLs
    import re
    all_urls_file = out / "urls" / "all_urls.txt"
    if all_urls_file.exists():
        params = set()
        for url in all_urls_file.read_text().splitlines():
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
def phase_nuclei(out: Path, scope_targets: list, severity: str, threads: int):
    console.print(Rule("[bold cyan]PHASE 6 — Nuclei Vulnerability Scanning[/bold cyan]"))

    live_urls = out / "hosts" / "live_urls.txt"
    nuclei_dir = out / "nuclei"

    # Filter live_urls to only scoped targets
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

    # Update templates
    with console.status("[cyan]Updating Nuclei templates...[/cyan]"):
        run_tool(["nuclei", "-update-templates", "-silent"], timeout=120)

    # Run scan
    findings = nuclei_dir / "findings.txt"
    findings_json = nuclei_dir / "findings.json"

    with console.status(f"[cyan]Running Nuclei (severity: {severity})...[/cyan]"):
        run_tool([
            "nuclei", "-l", str(scoped_file),
            "-severity", severity,
            "-c", str(threads),
            "-o", str(findings),
            "-json-export", str(findings_json),
            "-silent"
        ], timeout=900)

    if findings.exists():
        hits = count_lines(findings)
        console.print(f"[green][+][/green] Nuclei findings: [bold]{hits}[/bold]")

        # Separate critical/high
        import re
        crits = [l for l in findings.read_text().splitlines()
                 if re.search(r'\[(critical|high)\]', l, re.I)]
        (nuclei_dir / "critical_high.txt").write_text("\n".join(crits))
        if crits:
            console.print(f"[red][!][/red] Critical/High findings: [bold red]{len(crits)}[/bold red]")


# ─────────────────────────────────────────────────────────────
# Phase 7 — JS Secret Analysis
# ─────────────────────────────────────────────────────────────
def phase_js(out: Path):
    console.print(Rule("[bold cyan]PHASE 7 — JS & Secret Analysis[/bold cyan]"))
    import re
    import urllib.request

    js_dir = out / "js"
    js_files_list = js_dir / "js_files.txt"

    if not js_files_list.exists() or count_lines(js_files_list) == 0:
        console.print("[yellow][!][/yellow] No JS files found — skipping.")
        return

    files_dir = js_dir / "files"
    files_dir.mkdir(exist_ok=True)

    js_urls = js_files_list.read_text().splitlines()
    console.print(f"[green][+][/green] Downloading [bold]{len(js_urls)}[/bold] JS files...")

    secret_pattern = re.compile(
        r'(?:api.?key|apikey|secret|password|token|auth|bearer|aws_access|private.?key|client.?secret)'
        r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=_\-]{8,})',
        re.I
    )
    endpoint_pattern = re.compile(r'["\'](\s*/(?:api|v[0-9])[/a-zA-Z0-9_\-\.]+)["\']')

    secrets = []
    endpoints = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                  TextColumn("{task.completed}/{task.total}"), console=console) as progress:
        task = progress.add_task("[cyan]Analysing JS files...", total=len(js_urls))

        for url in js_urls:
            try:
                import hashlib
                fname = hashlib.md5(url.encode()).hexdigest()
                fpath = files_dir / f"{fname}.js"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read().decode("utf-8", errors="ignore")
                fpath.write_text(content)
                secrets.extend(secret_pattern.findall(content))
                endpoints.extend(endpoint_pattern.findall(content))
            except Exception:
                pass
            progress.advance(task)

    (js_dir / "potential_secrets.txt").write_text("\n".join(set(secrets)))
    (js_dir / "js_endpoints.txt").write_text("\n".join(set(endpoints)))
    console.print(f"[green][+][/green] Potential secrets: [bold]{len(set(secrets))}[/bold]")
    console.print(f"[green][+][/green] JS endpoints: [bold]{len(set(endpoints))}[/bold]")


# ─────────────────────────────────────────────────────────────
# Phase 8 — Report
# ─────────────────────────────────────────────────────────────
def phase_report(out: Path, domain: str, config: "Config"):
    console.print(Rule("[bold cyan]PHASE 8 — Generating Summary Report[/bold cyan]"))

    report = out / "reports" / "summary.md"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def c(f): return str(count_lines(out / f)) if (out / f).exists() else "0"

    content = f"""# Sayyad Recon Report — {domain}
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
| Parameters Discovered | {c("params/discovered_params.txt")} |
| Nuclei Findings | {c("nuclei/findings.txt")} |
| Critical/High | {c("nuclei/critical_high.txt")} |

---

## Critical/High Findings
"""
    crit_file = out / "nuclei" / "critical_high.txt"
    content += crit_file.read_text() if crit_file.exists() else "_None found._\n"

    content += "\n---\n## Potential Secrets in JS\n"
    sec_file = out / "js" / "potential_secrets.txt"
    content += "\n".join(sec_file.read_text().splitlines()[:20]) if sec_file.exists() else "_None found._\n"

    content += "\n---\n## Interesting Endpoints (top 30)\n"
    ep_file = out / "urls" / "interesting_endpoints.txt"
    content += "\n".join(ep_file.read_text().splitlines()[:30]) if ep_file.exists() else "_None found._\n"

    content += "\n\n---\n*Generated by Sayyad Recon Framework*\n"
    report.write_text(content)
    console.print(f"[green][+][/green] Report saved → [cyan]{report}[/cyan]")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="sayyad",
        description="Sayyad Recon Framework — Bug Bounty Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -d hackerone.com
  python3 recon.py -d hackerone.com --deep
  python3 recon.py -d hackerone.com --scan-scope all
  python3 recon.py -d hackerone.com --scan-scope targets.txt
  python3 recon.py -d hackerone.com --resume
  python3 recon.py -d hackerone.com --no-api-warnings
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default=str(Path.home() / "recon"), help="Output base directory")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("-s", "--severity", default="low,medium,high,critical", help="Nuclei severity filter")
    parser.add_argument("--deep", action="store_true", help="Deep mode: active Amass + full port scan")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument(
        "--scan-scope",
        default="main",
        metavar="SCOPE",
        help=(
            "Scope for deep scanning phases (crawl, params, nuclei).\n"
            "  main        — main domain only (default, safest)\n"
            "  all         — all discovered live subdomains\n"
            "  discovered  — interactively pick from discovered hosts\n"
            "  <file.txt>  — use a custom targets file"
        )
    )
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scanning")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip Nmap port scan")
    parser.add_argument("--skip-crawl", action="store_true", help="Skip URL crawling")
    parser.add_argument("--no-api-warnings", action="store_true", help="Suppress missing API key warnings")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    global _checkpoint, _domain, _out

    args = parse_args()
    _domain = args.domain

    # ── Load config ───────────────────────────────────────────
    config = Config.load(suppress_warnings=args.no_api_warnings)

    # ── Find / create output directory ────────────────────────
    base = Path(args.output) / args.domain
    base.mkdir(parents=True, exist_ok=True)

    # ── Checkpoint / resume logic ─────────────────────────────
    chk_mgr = CheckpointManager(base)
    _checkpoint = chk_mgr

    if args.resume:
        run_dir = chk_mgr.find_resumable()
        if run_dir:
            console.print(f"\n[green][+][/green] Resumable checkpoint found: [cyan]{run_dir}[/cyan]")
            chk_mgr.load(run_dir)
        else:
            console.print("[yellow][!][/yellow] No resumable checkpoint found — starting fresh.")
            args.resume = False

    if not args.resume:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = base / timestamp
        for sub in ["subdomains","hosts","urls","ports","nuclei","js","params","osint","reports"]:
            (run_dir / sub).mkdir(parents=True, exist_ok=True)
        chk_mgr.init(run_dir, args)

    _out = run_dir

    # ── Banner ────────────────────────────────────────────────
    banner()

    # ── Startup info table ────────────────────────────────────
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold")
    info.add_column()
    info.add_row("Target",    f"[bold cyan]{args.domain}[/bold cyan]")
    info.add_row("Output",    str(run_dir))
    info.add_row("Scan Scope", f"[yellow]{args.scan_scope}[/yellow]")
    info.add_row("Deep Mode", str(args.deep))
    info.add_row("Threads",   str(args.threads))
    info.add_row("Started",   datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(Panel(info, title="[bold]Run Configuration[/bold]", border_style="cyan"))
    console.print()

    # ── API key status ────────────────────────────────────────
    config.print_key_status(suppress=args.no_api_warnings)

    # ─────────────────────────────────────────────────────────
    # PHASE 1 — Subdomain Enumeration
    # ─────────────────────────────────────────────────────────
    if not chk_mgr.is_done("phase1"):
        console.print(Rule("[bold cyan]PHASE 1 — Subdomain Enumeration (14 Sources)[/bold cyan]"))
        subdomains = asyncio.run(
            enumerate_subdomains(args.domain, run_dir, config)
        )
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
    # Resolve scan scope AFTER we know live hosts
    # ─────────────────────────────────────────────────────────
    scope_mgr = ScopeManager(args.domain, live_hosts)
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
            phase_nuclei(run_dir, scope_targets, args.severity, args.threads)
            chk_mgr.complete("phase6", {})
        else:
            console.print(Rule("[dim]PHASE 6 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE 7 — JS Analysis
    # ─────────────────────────────────────────────────────────
    if not chk_mgr.is_done("phase7"):
        phase_js(run_dir)
        chk_mgr.complete("phase7", {})
    else:
        console.print(Rule("[dim]PHASE 7 — Skipped (checkpoint)[/dim]"))

    # ─────────────────────────────────────────────────────────
    # PHASE 8 — Report
    # ─────────────────────────────────────────────────────────
    phase_report(run_dir, args.domain, config)
    chk_mgr.mark_complete()

    # ── Final summary ─────────────────────────────────────────
    console.print()
    console.print(Panel(
        f"[bold green]✅  RECON COMPLETE[/bold green]\n\n"
        f"  Domain     : [bold]{args.domain}[/bold]\n"
        f"  Subdomains : [bold]{count_lines(run_dir / 'subdomains' / 'all_subdomains.txt')}[/bold]\n"
        f"  Live Hosts : [bold]{count_lines(run_dir / 'hosts' / 'live_urls.txt')}[/bold]\n"
        f"  Findings   : [bold red]{count_lines(run_dir / 'nuclei' / 'findings.txt')}[/bold red] "
        f"([red]{count_lines(run_dir / 'nuclei' / 'critical_high.txt')} Crit/High[/red])\n"
        f"  Secrets    : [bold yellow]{count_lines(run_dir / 'js' / 'potential_secrets.txt')}[/bold yellow] potential\n\n"
        f"  Output     : [cyan]{run_dir}[/cyan]\n"
        f"  Report     : [cyan]{run_dir / 'reports' / 'summary.md'}[/cyan]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()