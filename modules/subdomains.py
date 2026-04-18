"""
modules/subdomains.py — Async subdomain enumeration (14 sources)

All curl-based sources run concurrently via aiohttp.
Tool-based sources (subfinder, assetfinder) run in parallel threads.
Results are merged, deduplicated, and validated.
"""

import asyncio
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Set

import aiohttp
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

console = Console()

# Timeouts (seconds)
TIMEOUT_API  = 45
TIMEOUT_TOOL = 180

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SayadRecon/2.0)"}


def _clean(raw: str, domain: str) -> Set[str]:
    """Extract and normalise valid subdomains from raw text."""
    escaped = re.escape(domain)
    pattern = re.compile(
        r'(?:[a-zA-Z0-9_-]+\.)+' + escaped + r'(?:\b|$)',
        re.I
    )
    found = set()
    for match in pattern.findall(raw):
        sub = match.strip().lstrip("*.").lower()
        if sub.endswith(f".{domain}") or sub == domain:
            found.add(sub)
    return found


# ════════════════════════════════════════════════════════════
# API Sources (async)
# ════════════════════════════════════════════════════════════

async def fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """Certificate Transparency logs via crt.sh"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            found = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    cleaned = name.strip().lstrip("*.").lower()
                    if cleaned.endswith(f".{domain}") or cleaned == domain:
                        found.add(cleaned)
            return found
    except Exception:
        return set()


async def fetch_wayback(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """Wayback Machine CDX API for historical subdomains"""
    try:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=50000"
        )
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
            text = await r.text()
            return _clean(text, domain)
    except Exception:
        return set()


async def fetch_otx(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """AlienVault OTX passive DNS"""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            found = set()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").lower().lstrip("*.")
                if hostname.endswith(f".{domain}") or hostname == domain:
                    found.add(hostname)
            return found
    except Exception:
        return set()


async def fetch_hackertarget(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """HackerTarget host search"""
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            text = await r.text()
            if "error" in text.lower() or "limit" in text.lower():
                return set()
            return _clean(text, domain)
    except Exception:
        return set()


async def fetch_rapiddns(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """RapidDNS subdomain dataset"""
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            text = await r.text()
            return _clean(text, domain)
    except Exception:
        return set()


async def fetch_urlscan(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """URLScan.io browser scan archive"""
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
        async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            found = set()
            for result in data.get("results", []):
                d = result.get("page", {}).get("domain", "").lower()
                if d.endswith(f".{domain}") or d == domain:
                    found.add(d)
            return found
    except Exception:
        return set()


async def fetch_threatcrowd(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    """ThreatCrowd domain report"""
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            subs = data.get("subdomains", [])
            return _clean(" ".join(subs), domain)
    except Exception:
        return set()


async def fetch_shodan(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """Shodan DNS + SSL certificate search"""
    found = set()
    try:
        # DNS endpoint
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            for sub in data.get("subdomains", []):
                full = f"{sub.strip('.')}.{domain}" if not sub.endswith(domain) else sub.lower()
                found.add(full.lower())
    except Exception:
        pass
    return found


async def fetch_virustotal(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """VirusTotal subdomain dataset (paginated)"""
    found = set()
    cursor = ""
    headers = {**HEADERS, "x-apikey": api_key}
    try:
        for _ in range(5):  # max 5 pages
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
            if cursor:
                url += f"&cursor={cursor}"
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
                data = await r.json(content_type=None)
                for entry in data.get("data", []):
                    sub = entry.get("id", "").lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.add(sub)
                cursor = data.get("meta", {}).get("cursor", "")
                if not cursor:
                    break
    except Exception:
        pass
    return found


async def fetch_securitytrails(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """SecurityTrails subdomain history"""
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?include_inactive=true"
        headers = {**HEADERS, "apikey": api_key}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            found = set()
            for sub in data.get("subdomains", []):
                found.add(f"{sub.strip('.')}.{domain}".lower())
            return found
    except Exception:
        return set()


async def fetch_bevigil(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """BeVigil mobile app intel"""
    try:
        url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
        headers = {**HEADERS, "X-Access-Token": api_key}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            return _clean(json.dumps(data), domain)
    except Exception:
        return set()


async def fetch_leakix(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    """LeakIX subdomain intelligence"""
    try:
        url = f"https://leakix.net/api/subdomains/{domain}"
        headers = {**HEADERS, "api-key": api_key, "Accept": "application/json"}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            data = await r.json(content_type=None)
            return _clean(json.dumps(data), domain)
    except Exception:
        return set()


# ════════════════════════════════════════════════════════════
# Tool-based Sources (subprocess, run in threads)
# ════════════════════════════════════════════════════════════

def run_subfinder(domain: str, threads: int) -> Set[str]:
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-t", str(threads)],
            capture_output=True, text=True, timeout=TIMEOUT_TOOL
        )
        return _clean(result.stdout, domain)
    except Exception:
        return set()


def run_assetfinder(domain: str) -> Set[str]:
    try:
        result = subprocess.run(
            ["assetfinder", "--subs-only", domain],
            capture_output=True, text=True, timeout=TIMEOUT_TOOL
        )
        return _clean(result.stdout, domain)
    except Exception:
        return set()


def run_amass(domain: str) -> Set[str]:
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "20"],
            capture_output=True, text=True, timeout=TIMEOUT_TOOL
        )
        return _clean(result.stdout, domain)
    except Exception:
        return set()


# ════════════════════════════════════════════════════════════
# Main enumeration orchestrator
# ════════════════════════════════════════════════════════════

async def enumerate_subdomains(domain: str, out: Path, config) -> Set[str]:
    """
    Run all 14 sources in parallel:
      - API sources → async aiohttp (simultaneous HTTP requests)
      - Tool sources → ThreadPoolExecutor (parallel subprocesses)
    """
    subs_dir = out / "subdomains"
    all_results: dict[str, Set[str]] = {}

    source_names = [
        "crt.sh", "wayback", "otx", "hackertarget", "rapiddns",
        "urlscan", "threatcrowd",
        "shodan" if config.shodan_api_key else None,
        "virustotal" if config.virustotal_api_key else None,
        "securitytrails" if config.securitytrails_api_key else None,
        "bevigil" if config.bevigil_api_key else None,
        "leakix" if config.leakix_api_key else None,
        "subfinder", "assetfinder",
    ]
    active_sources = [s for s in source_names if s]

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task(
            f"Enumerating {len(active_sources)} sources...",
            total=len(active_sources)
        )

        # ── Run API sources concurrently ──────────────────────
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:

            api_tasks = {
                "crt.sh":        fetch_crtsh(session, domain),
                "wayback":       fetch_wayback(session, domain),
                "otx":           fetch_otx(session, domain),
                "hackertarget":  fetch_hackertarget(session, domain),
                "rapiddns":      fetch_rapiddns(session, domain),
                "urlscan":       fetch_urlscan(session, domain),
                "threatcrowd":   fetch_threatcrowd(session, domain),
            }

            if config.shodan_api_key:
                api_tasks["shodan"] = fetch_shodan(session, domain, config.shodan_api_key)
            if config.virustotal_api_key:
                api_tasks["virustotal"] = fetch_virustotal(session, domain, config.virustotal_api_key)
            if config.securitytrails_api_key:
                api_tasks["securitytrails"] = fetch_securitytrails(session, domain, config.securitytrails_api_key)
            if config.bevigil_api_key:
                api_tasks["bevigil"] = fetch_bevigil(session, domain, config.bevigil_api_key)
            if config.leakix_api_key:
                api_tasks["leakix"] = fetch_leakix(session, domain, config.leakix_api_key)

            # Gather all API results
            api_results = await asyncio.gather(
                *api_tasks.values(),
                return_exceptions=True
            )

            for name, result in zip(api_tasks.keys(), api_results):
                found = result if isinstance(result, set) else set()
                all_results[name] = found
                (subs_dir / f"{name.replace('.','')}.txt").write_text("\n".join(sorted(found)))
                progress.advance(task)

        # ── Run tool sources in thread pool ───────────────────
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=3) as executor:
            subfinder_fut   = loop.run_in_executor(executor, run_subfinder, domain, 50)
            assetfinder_fut = loop.run_in_executor(executor, run_assetfinder, domain)

            subfinder_res   = await subfinder_fut
            assetfinder_res = await assetfinder_fut

            all_results["subfinder"]   = subfinder_res
            all_results["assetfinder"] = assetfinder_res

            (subs_dir / "subfinder.txt").write_text("\n".join(sorted(subfinder_res)))
            (subs_dir / "assetfinder.txt").write_text("\n".join(sorted(assetfinder_res)))

            progress.advance(task)
            progress.advance(task)

    # ── Per-source breakdown table ────────────────────────────
    table = Table(title="Source Breakdown", border_style="dim", title_style="bold")
    table.add_column("Source",  style="cyan",  width=18)
    table.add_column("Found",   style="bold",  justify="right", width=8)
    table.add_column("Status",  width=14)

    for name, found in sorted(all_results.items(), key=lambda x: -len(x[1])):
        count = len(found)
        status = "[green]✓[/green]" if count > 0 else "[dim]–[/dim]"
        table.add_row(name, str(count), status)

    console.print(table)

    # ── Merge all results ─────────────────────────────────────
    merged: Set[str] = set()
    for subs in all_results.values():
        merged.update(subs)

    return merged