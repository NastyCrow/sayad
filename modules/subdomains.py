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
from typing import Optional, Set, Tuple

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


# ── Error-aware fetch wrapper ─────────────────────────────────

async def _fetch(name: str, coro_factory, max_retries: int = 2) -> Tuple[str, Set[str], Optional[str]]:
    """
    Run a source coroutine factory and return (name, results, error_msg).

    coro_factory is a zero-argument callable that returns a fresh coroutine
    each time it is called (allows clean retries without reusing a spent coro).

    Retries up to max_retries times on transient 5xx server errors (e.g. crt.sh 502)
    with exponential backoff (1 s, 2 s, …).
    """
    last_error: Optional[str] = None
    for attempt in range(max_retries + 1):
        try:
            result = await coro_factory()
            return name, result, None
        except aiohttp.ClientResponseError as e:
            if e.status in (401, 403):
                return name, set(), "unauthorized — check API key"
            if e.status == 429:
                return name, set(), "rate limited"
            if e.status >= 500:
                last_error = f"server error ({e.status})"
                if attempt < max_retries:
                    await asyncio.sleep(2.0 ** attempt)   # 1 s → 2 s → …
                    continue
                return name, set(), last_error
            return name, set(), f"HTTP {e.status}"
        except asyncio.TimeoutError:
            return name, set(), "timed out"
        except aiohttp.ClientConnectionError:
            return name, set(), "connection failed"
        except Exception as exc:
            return name, set(), str(exc)[:60]
    return name, set(), last_error or "unknown error"


# ════════════════════════════════════════════════════════════
# API Sources (async — internal try/except removed so _fetch can categorise)
# ════════════════════════════════════════════════════════════

async def fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        found = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                cleaned = name.strip().lstrip("*.").lower()
                if cleaned.endswith(f".{domain}") or cleaned == domain:
                    found.add(cleaned)
        return found


async def fetch_wayback(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=50000"
    )
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
        r.raise_for_status()
        text = await r.text()
        return _clean(text, domain)


async def fetch_otx(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        found = set()
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").lower().lstrip("*.")
            if hostname.endswith(f".{domain}") or hostname == domain:
                found.add(hostname)
        return found


async def fetch_hackertarget(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        text = await r.text()
        if "error" in text.lower() or "limit" in text.lower():
            return set()
        return _clean(text, domain)


async def fetch_rapiddns(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        text = await r.text()
        return _clean(text, domain)


async def fetch_urlscan(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
    async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        found = set()
        for result in data.get("results", []):
            d = result.get("page", {}).get("domain", "").lower()
            if d.endswith(f".{domain}") or d == domain:
                found.add(d)
        return found


async def fetch_threatcrowd(session: aiohttp.ClientSession, domain: str) -> Set[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        subs = data.get("subdomains", [])
        return _clean(" ".join(subs), domain)


async def fetch_shodan(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        found = set()
        for sub in data.get("subdomains", []):
            full = f"{sub.strip('.')}.{domain}" if not sub.endswith(domain) else sub.lower()
            found.add(full.lower())
        return found


async def fetch_virustotal(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    found = set()
    cursor = ""
    headers = {**HEADERS, "x-apikey": api_key}
    for _ in range(5):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        if cursor:
            url += f"&cursor={cursor}"
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
            r.raise_for_status()
            data = await r.json(content_type=None)
            for entry in data.get("data", []):
                sub = entry.get("id", "").lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    found.add(sub)
            cursor = data.get("meta", {}).get("cursor", "")
            if not cursor:
                break
    return found


async def fetch_securitytrails(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?include_inactive=true"
    headers = {**HEADERS, "apikey": api_key}
    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        return {f"{sub.strip('.')}.{domain}".lower() for sub in data.get("subdomains", [])}


async def fetch_bevigil(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
    headers = {**HEADERS, "X-Access-Token": api_key}
    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        return _clean(json.dumps(data), domain)


async def fetch_leakix(session: aiohttp.ClientSession, domain: str, api_key: str) -> Set[str]:
    url = f"https://leakix.net/api/subdomains/{domain}"
    headers = {**HEADERS, "api-key": api_key, "Accept": "application/json"}
    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT_API)) as r:
        r.raise_for_status()
        data = await r.json(content_type=None)
        return _clean(json.dumps(data), domain)


# ════════════════════════════════════════════════════════════
# Tool-based Sources (subprocess, run in threads)
# ════════════════════════════════════════════════════════════

def run_subfinder(domain: str, threads: int) -> Tuple[Set[str], Optional[str]]:
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-t", str(threads)],
            capture_output=True, text=True, timeout=TIMEOUT_TOOL
        )
        if result.returncode != 0 and not result.stdout.strip():
            return set(), f"exit {result.returncode}"
        return _clean(result.stdout, domain), None
    except FileNotFoundError:
        return set(), "not installed"
    except subprocess.TimeoutExpired:
        return set(), "timed out"
    except Exception as exc:
        return set(), str(exc)[:60]


def run_assetfinder(domain: str) -> Tuple[Set[str], Optional[str]]:
    try:
        result = subprocess.run(
            ["assetfinder", "--subs-only", domain],
            capture_output=True, text=True, timeout=TIMEOUT_TOOL
        )
        if result.returncode != 0 and not result.stdout.strip():
            return set(), f"exit {result.returncode}"
        return _clean(result.stdout, domain), None
    except FileNotFoundError:
        return set(), "not installed"
    except subprocess.TimeoutExpired:
        return set(), "timed out"
    except Exception as exc:
        return set(), str(exc)[:60]


def run_amass(domain: str) -> Tuple[Set[str], Optional[str]]:
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "20"],
            capture_output=True, text=True, timeout=TIMEOUT_TOOL
        )
        return _clean(result.stdout, domain), None
    except FileNotFoundError:
        return set(), "not installed"
    except subprocess.TimeoutExpired:
        return set(), "timed out"
    except Exception as exc:
        return set(), str(exc)[:60]


# ════════════════════════════════════════════════════════════
# Main enumeration orchestrator
# ════════════════════════════════════════════════════════════

async def enumerate_subdomains(domain: str, out: Path, config) -> Set[str]:
    """
    Run all sources in parallel:
      - API sources → async aiohttp
      - Tool sources → ThreadPoolExecutor
    """
    subs_dir = out / "subdomains"
    all_results: dict   = {}   # source → Set[str]
    all_errors:  dict   = {}   # source → Optional[str]

    source_names = [
        "crt.sh", "wayback", "otx", "hackertarget", "rapiddns",
        "urlscan", "threatcrowd",
        "shodan"         if config.shodan_api_key         else None,
        "virustotal"     if config.virustotal_api_key     else None,
        "securitytrails" if config.securitytrails_api_key else None,
        "bevigil"        if config.bevigil_api_key        else None,
        "leakix"         if config.leakix_api_key         else None,
        "subfinder", "assetfinder",
    ]
    active_sources = [s for s in source_names if s]

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            f"Enumerating {len(active_sources)} sources...",
            total=len(active_sources),
        )

        # ── API sources ───────────────────────────────────────
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:

            # Factories (zero-arg callables) so _fetch can create a fresh coroutine
            # on each retry without reusing a spent coroutine object.
            api_factories: dict = {
                "crt.sh":       lambda: fetch_crtsh(session, domain),
                "wayback":      lambda: fetch_wayback(session, domain),
                "otx":          lambda: fetch_otx(session, domain),
                "hackertarget": lambda: fetch_hackertarget(session, domain),
                "rapiddns":     lambda: fetch_rapiddns(session, domain),
                "urlscan":      lambda: fetch_urlscan(session, domain),
                "threatcrowd":  lambda: fetch_threatcrowd(session, domain),
            }
            if config.shodan_api_key:
                _k = config.shodan_api_key
                api_factories["shodan"] = lambda: fetch_shodan(session, domain, _k)
            if config.virustotal_api_key:
                _k = config.virustotal_api_key
                api_factories["virustotal"] = lambda: fetch_virustotal(session, domain, _k)
            if config.securitytrails_api_key:
                _k = config.securitytrails_api_key
                api_factories["securitytrails"] = lambda: fetch_securitytrails(session, domain, _k)
            if config.bevigil_api_key:
                _k = config.bevigil_api_key
                api_factories["bevigil"] = lambda: fetch_bevigil(session, domain, _k)
            if config.leakix_api_key:
                _k = config.leakix_api_key
                api_factories["leakix"] = lambda: fetch_leakix(session, domain, _k)

            wrapped = [_fetch(name, factory) for name, factory in api_factories.items()]
            api_results = await asyncio.gather(*wrapped)

            for name, found, error in api_results:
                all_results[name] = found
                all_errors[name]  = error
                (subs_dir / f"{name.replace('.','')}.txt").write_text("\n".join(sorted(found)))
                progress.advance(task)

        # ── Tool sources ──────────────────────────────────────
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=3) as executor:
            sf_fut = loop.run_in_executor(executor, run_subfinder, domain, 50)
            af_fut = loop.run_in_executor(executor, run_assetfinder, domain)

            sf_found, sf_err = await sf_fut
            af_found, af_err = await af_fut

            all_results["subfinder"]   = sf_found
            all_results["assetfinder"] = af_found
            all_errors["subfinder"]    = sf_err
            all_errors["assetfinder"]  = af_err

            (subs_dir / "subfinder.txt").write_text("\n".join(sorted(sf_found)))
            (subs_dir / "assetfinder.txt").write_text("\n".join(sorted(af_found)))

            progress.advance(task)
            progress.advance(task)

    # ── Per-source breakdown table ────────────────────────────
    table = Table(title="Source Breakdown", border_style="dim", title_style="bold")
    table.add_column("Source",  style="cyan", width=18)
    table.add_column("Found",   style="bold", justify="right", width=8)
    table.add_column("Status",  width=30)

    for name, found in sorted(all_results.items(), key=lambda x: -len(x[1])):
        count = len(found)
        err   = all_errors.get(name)
        if err:
            status = f"[red]✗ {err}[/red]"
        elif count > 0:
            status = "[green]✓[/green]"
        else:
            status = "[dim]– (no results)[/dim]"
        table.add_row(name, str(count), status)

    console.print(table)

    # ── Merge ─────────────────────────────────────────────────
    merged: Set[str] = set()
    for subs in all_results.values():
        merged.update(subs)
    return merged
