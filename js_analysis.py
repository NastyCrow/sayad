#!/usr/bin/env python3
"""
╔════════════════════════════════════════════╗
║  Sayyad — Standalone JS Analyser           ║
║  Run JS analysis on any completed scan dir ║
╚════════════════════════════════════════════╝

Usage:
  python3 js_analyze.py --scan-dir ~/recon/ejada.com/20260416_093150
  python3 js_analyze.py --scan-dir ~/recon/ejada.com/20260416_093150 --llm
  python3 js_analyze.py --domain ejada.com          # auto-finds latest scan
  python3 js_analyze.py --domain ejada.com --llm
"""

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path

# ── Fix module path ───────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from rich.console import Console
    from rich.rule import Rule
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("[!] Missing dependencies: pip install rich aiohttp pyyaml")
    sys.exit(1)

console = Console()

# ── Secret patterns ───────────────────────────────────────────
SECRET_PATTERNS = [
    (re.compile(r'(?:api.?key|apikey|api-key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})', re.I), "API Key"),
    (re.compile(r'(?:secret|client.?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})', re.I), "Secret"),
    (re.compile(r'(?:password|passwd)["\']?\s*[:=]\s*["\']([^\'"]{6,})', re.I), "Password"),
    (re.compile(r'(?:token|auth.?token|access.?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})', re.I), "Token"),
    (re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]{20,})', re.I), "Bearer Token"),
    (re.compile(r'AKIA[0-9A-Z]{16}', re.I), "AWS Access Key"),
    (re.compile(r'(?:aws.?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9+/]{40})', re.I), "AWS Secret"),
    (re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'), "JWT Token"),
    (re.compile(r'(?:private.?key|rsa.?key)["\']?\s*[:=]\s*["\']([^\'"]{20,})', re.I), "Private Key"),
    (re.compile(r'(?:firebase|fb)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-]{30,})', re.I), "Firebase Key"),
    (re.compile(r'(?:slack.?token|xox[baprs]-[0-9A-Za-z\-]+)', re.I), "Slack Token"),
    (re.compile(r'(?:github.?token|ghp_[A-Za-z0-9]{36})', re.I), "GitHub Token"),
]

ENDPOINT_PATTERN = re.compile(
    r'''['"]((?:/api/|/v[0-9]+/|/graphql|/rest/|/admin/|/internal/)[a-zA-Z0-9/_\-\.]{3,})['"']''',
)

SENSITIVE_PATTERN = re.compile(
    r'''['"]((?:/[a-zA-Z0-9/_\-\.]*(?:password|secret|key|token|auth|admin|debug|config|backup|internal)[a-zA-Z0-9/_\-\.]*))['"]''',
    re.I
)


def find_latest_scan(domain: str, base_dir: Path) -> Path:
    """Auto-find the most recent scan directory for a domain."""
    domain_dir = base_dir / domain
    if not domain_dir.exists():
        console.print(f"[red][✗][/red] No scan directory found for [bold]{domain}[/bold] in {base_dir}")
        sys.exit(1)

    candidates = sorted(
        [d for d in domain_dir.iterdir() if d.is_dir()],
        reverse=True
    )
    if not candidates:
        console.print(f"[red][✗][/red] No scan runs found for {domain}")
        sys.exit(1)

    latest = candidates[0]
    console.print(f"[green][+][/green] Auto-selected latest scan: [cyan]{latest}[/cyan]")
    return latest


def download_js(js_files: list, files_dir: Path) -> list:
    """Download JS files, skip already cached."""
    downloaded = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Downloading JS files...", total=len(js_files))

        for url in js_files:
            url = url.strip()
            if not url:
                progress.advance(task)
                continue

            fname = hashlib.md5(url.encode()).hexdigest() + ".js"
            fpath = files_dir / fname

            # Use cached version if available
            if fpath.exists() and fpath.stat().st_size > 0:
                downloaded.append((url, fpath))
                progress.advance(task)
                continue

            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read().decode("utf-8", errors="ignore")
                if content.strip():
                    fpath.write_text(content)
                    downloaded.append((url, fpath))
            except Exception:
                pass
            progress.advance(task)

    return downloaded


def analyse_js_files(downloaded: list) -> tuple:
    """Scan JS files for secrets and endpoints. Returns (secrets, endpoints)."""
    secrets = []
    endpoints = set()
    sensitive = set()

    for url, fpath in downloaded:
        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue

        # Secrets
        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                val = match.group(1) if match.lastindex else match.group(0)
                if len(val) > 6:
                    secrets.append({
                        "type":   label,
                        "value":  val[:60] + ("..." if len(val) > 60 else ""),
                        "source": url
                    })

        # API endpoints
        for match in ENDPOINT_PATTERN.finditer(content):
            endpoints.add(match.group(1))

        # Sensitive paths
        for match in SENSITIVE_PATTERN.finditer(content):
            sensitive.add(match.group(1))

    return secrets, sorted(endpoints), sorted(sensitive)


def save_results(scan_dir: Path, secrets: list, endpoints: list, sensitive: list):
    """Write analysis results to the js/ directory."""
    js_dir = scan_dir / "js"

    # Secrets — include type and source
    secrets_lines = [f"[{s['type']}] {s['value']}  (from: {s['source']})" for s in secrets]
    (js_dir / "potential_secrets.txt").write_text("\n".join(secrets_lines))

    # Endpoints
    (js_dir / "js_endpoints.txt").write_text("\n".join(endpoints))

    # Sensitive paths
    (js_dir / "js_sensitive_paths.txt").write_text("\n".join(sensitive))


def print_results(secrets: list, endpoints: list, sensitive: list):
    """Display a Rich summary table of findings."""
    console.print()

    # Secrets table
    if secrets:
        t = Table(title=f"[bold red]Potential Secrets ({len(secrets)})[/bold red]",
                  border_style="red", show_lines=True)
        t.add_column("Type", style="bold yellow", width=18)
        t.add_column("Value", width=45)
        t.add_column("Source", style="dim cyan")
        for s in secrets[:30]:  # show top 30
            t.add_row(s["type"], s["value"], s["source"].split("/")[-1])
        console.print(t)
    else:
        console.print("[dim]  No secrets found.[/dim]")

    # Endpoints table
    if endpoints:
        t = Table(title=f"[bold cyan]API Endpoints ({len(endpoints)})[/bold cyan]",
                  border_style="cyan")
        t.add_column("Endpoint", style="cyan")
        for ep in endpoints[:50]:
            t.add_row(ep)
        console.print(t)

    # Sensitive paths
    if sensitive:
        t = Table(title=f"[bold yellow]Sensitive Paths ({len(sensitive)})[/bold yellow]",
                  border_style="yellow")
        t.add_column("Path", style="yellow")
        for p in sensitive[:30]:
            t.add_row(p)
        console.print(t)


def main():
    parser = argparse.ArgumentParser(
        prog="js_analyze",
        description="Sayyad — Standalone JS Analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyse a specific scan directory
  python3 js_analyze.py --scan-dir ~/recon/ejada.com/20260416_093150

  # Auto-find the latest scan for a domain
  python3 js_analyze.py --domain ejada.com

  # Analyse + feed results to local LLM
  python3 js_analyze.py --domain ejada.com --llm

  # Use a different model
  python3 js_analyze.py --domain ejada.com --llm --llm-model mistral
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan-dir", metavar="DIR",
                       help="Path to a specific scan output directory")
    group.add_argument("--domain", metavar="DOMAIN",
                       help="Domain name — auto-selects the latest scan")

    parser.add_argument("--output-base", default=str(Path.home() / "recon"),
                        help="Base recon directory (default: ~/recon)")
    parser.add_argument("--llm", action="store_true",
                        help="Send results to local LLM (Ollama) for analysis")
    parser.add_argument("--llm-model", default="llama3",
                        help="Ollama model to use (default: llama3)")
    parser.add_argument("--llm-url", default="http://localhost:11434",
                        help="Ollama API URL (default: http://localhost:11434)")
    parser.add_argument("--re-download", action="store_true",
                        help="Force re-download of all JS files (ignores cache)")

    args = parser.parse_args()

    # ── Banner ────────────────────────────────────────────────
    console.print(Panel(
        "[bold cyan]Sayyad — Standalone JS Analyser[/bold cyan]\n"
        "Secrets · API Endpoints · Sensitive Paths · LLM Analysis",
        border_style="cyan"
    ))

    # ── Resolve scan directory ────────────────────────────────
    if args.scan_dir:
        scan_dir = Path(args.scan_dir).expanduser().resolve()
        if not scan_dir.exists():
            console.print(f"[red][✗][/red] Directory not found: {scan_dir}")
            sys.exit(1)
        domain = scan_dir.parent.name
    else:
        scan_dir = find_latest_scan(args.domain, Path(args.output_base).expanduser())
        domain = args.domain

    js_dir = scan_dir / "js"
    js_dir.mkdir(exist_ok=True)
    files_dir = js_dir / "files"
    files_dir.mkdir(exist_ok=True)

    # ── Clear cache if re-download requested ──────────────────
    if args.re_download:
        for f in files_dir.glob("*.js"):
            f.unlink()
        console.print("[yellow][!][/yellow] Cache cleared — re-downloading all JS files.")

    # ── Load JS file list ─────────────────────────────────────
    js_list_file = js_dir / "js_files.txt"
    if not js_list_file.exists() or not js_list_file.read_text().strip():
        console.print("[yellow][!][/yellow] No JS files list found.")
        console.print(f"    Expected: [cyan]{js_list_file}[/cyan]")
        console.print("    Run a full scan first, or check that Phase 4 (crawling) completed.")
        sys.exit(1)

    js_files = [l for l in js_list_file.read_text().splitlines() if l.strip()]
    console.print(f"[green][+][/green] Found [bold]{len(js_files)}[/bold] JS files to analyse")
    console.print(f"[green][+][/green] Target: [bold]{domain}[/bold]  |  Scan: [cyan]{scan_dir.name}[/cyan]\n")

    # ── Download ──────────────────────────────────────────────
    console.print(Rule("[bold]Step 1 — Download[/bold]"))
    downloaded = download_js(js_files, files_dir)
    console.print(f"[green][+][/green] Downloaded/cached: [bold]{len(downloaded)}[/bold] files")

    if not downloaded:
        console.print("[yellow][!][/yellow] Nothing to analyse — all downloads failed.")
        sys.exit(0)

    # ── Analyse ───────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold]Step 2 — Analyse[/bold]"))
    with console.status("[cyan]Scanning for secrets and endpoints...[/cyan]"):
        secrets, endpoints, sensitive = analyse_js_files(downloaded)

    console.print(f"[green][+][/green] Potential secrets : [bold red]{len(secrets)}[/bold red]")
    console.print(f"[green][+][/green] API endpoints     : [bold cyan]{len(endpoints)}[/bold cyan]")
    console.print(f"[green][+][/green] Sensitive paths   : [bold yellow]{len(sensitive)}[/bold yellow]")

    # ── Save ──────────────────────────────────────────────────
    save_results(scan_dir, secrets, endpoints, sensitive)
    console.print(f"\n[green][+][/green] Results saved → [cyan]{js_dir}[/cyan]")

    # ── Display ───────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold]Step 3 — Results[/bold]"))
    print_results(secrets, endpoints, sensitive)

    # ── LLM Analysis ─────────────────────────────────────────
    if args.llm:
        console.print()
        console.print(Rule("[bold cyan]Step 4 — LLM Analysis[/bold cyan]"))
        from modules.llm import LLMAnalyzer
        analyzer = LLMAnalyzer(
            model=args.llm_model,
            base_url=args.llm_url,
            console=console
        )
        # Only run JS-relevant analyses
        if analyzer.is_available():
            llm_dir = scan_dir / "llm_analysis"
            llm_dir.mkdir(exist_ok=True)

            js_tasks = [
                ("secrets",      scan_dir / "js" / "potential_secrets.txt",   80),
                ("js_endpoints", scan_dir / "js" / "js_endpoints.txt",       100),
            ]
            from modules.llm import PROMPTS
            for analysis_type, data_file, max_lines in js_tasks:
                data = analyzer._read(data_file, max_lines)
                if not data:
                    continue
                console.print(f"[cyan]  → Analysing {analysis_type} with {args.llm_model}...[/cyan]")
                prompt = PROMPTS[analysis_type].format(domain=domain, data=data)
                response = analyzer.ask(prompt, context_label=analysis_type)
                if response:
                    out = llm_dir / f"js_{analysis_type}.md"
                    out.write_text(f"# JS LLM Analysis — {analysis_type} ({domain})\n\n{response}\n")
                    console.print(f"[green]  ✓[/green] Saved → [cyan]{out.name}[/cyan]")

    console.print()
    console.print(Panel(
        f"[bold green]✅  JS Analysis Complete[/bold green]\n\n"
        f"  Domain    : [bold]{domain}[/bold]\n"
        f"  Secrets   : [bold red]{len(secrets)}[/bold red]\n"
        f"  Endpoints : [bold cyan]{len(endpoints)}[/bold cyan]\n"
        f"  Sensitive : [bold yellow]{len(sensitive)}[/bold yellow]\n\n"
        f"  Output    : [cyan]{js_dir}[/cyan]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()