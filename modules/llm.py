"""
modules/llm.py — Local LLM integration via Ollama

Feeds scan output into a locally running LLM (Ollama) for AI-powered
security analysis. Runs entirely offline — no data leaves your machine.

Supported models (install via: ollama pull <model>):
  llama3         — best general analysis, recommended
  mistral        — fast, good for structured output
  codellama      — best for JS/code analysis
  deepseek-coder — strong on secrets and code review

Install Ollama: https://ollama.com/download
Then: ollama pull llama3
"""

import json
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


# ── Prompt templates for each analysis type ──────────────────
PROMPTS = {

    "subdomains": """You are an expert bug bounty hunter performing attack surface analysis.
I will give you a list of subdomains discovered for {domain}. Your job is to:
1. Identify high-value targets (admin, api, dev, staging, internal, vpn, mail, etc.)
2. Flag any subdomains that suggest sensitive infrastructure
3. Suggest which subdomains to prioritise for deeper testing and why
4. Note any patterns that suggest technology stack or organisational structure

Be concise and actionable. Format as: Priority tier → subdomain → reason.

Subdomains:
{data}""",

    "endpoints": """You are an expert web application security tester.
I will give you a list of interesting URLs/endpoints found on {domain}.
Your job is to:
1. Identify endpoints that are likely vulnerable to IDOR, auth bypass, injection, or information disclosure
2. Flag API endpoints that may lack proper authentication
3. Spot any admin/debug/backup endpoints that should not be public
4. Identify file extensions or patterns suggesting sensitive data exposure (.json, .xml, .env, .git, .bak)
5. Suggest specific attacks to try on each high-priority endpoint

Format as: Endpoint → Suspected Vulnerability → Attack to try.

Endpoints:
{data}""",

    "secrets": """You are a senior security researcher specialising in secrets detection.
I will give you potential secrets/credentials found in JavaScript files on {domain}.
Your job is to:
1. Triage each finding — is it a real secret or a false positive?
2. Identify the type of credential (API key, JWT, AWS key, OAuth token, etc.)
3. Assess the likely impact if valid (e.g. "AWS key — full account takeover possible")
4. Suggest immediate remediation steps
5. Identify which findings to validate first (highest impact)

Be direct and prioritise ruthlessly.

Potential secrets:
{data}""",

    "nuclei": """You are a vulnerability researcher analysing automated scan results.
I will give you Nuclei findings from {domain}.
Your job is to:
1. Assess which findings are most likely to be valid (not false positives)
2. Explain the real-world impact of each finding
3. Suggest exploitation steps for the highest severity findings
4. Identify any chains — vulnerabilities that could be combined for greater impact
5. Recommend which findings to include in a bug bounty report

Format as: Finding → Validity Assessment → Impact → Exploitation path.

Nuclei findings:
{data}""",

    "js_endpoints": """You are an expert in web application security and JavaScript analysis.
I will give you API endpoints extracted from JavaScript files on {domain}.
Your job is to:
1. Identify endpoints that suggest hidden or undocumented API functionality
2. Flag endpoints that may be vulnerable to IDOR (look for IDs, UUIDs, user references)
3. Identify endpoints that suggest admin or privileged functionality
4. Spot versioned APIs that may have older, less secure versions accessible
5. Suggest testing approaches for the most interesting endpoints

Format as: Endpoint → Risk → Testing approach.

JS endpoints:
{data}""",

    "summary": """You are a senior bug bounty hunter writing a triage summary.
Based on the following recon data for {domain}, provide:

1. EXECUTIVE SUMMARY — What is the attack surface? (2-3 sentences)
2. TOP 5 PRIORITIES — The 5 highest-value targets to investigate first
3. ATTACK CHAINS — Any combinations of findings that could chain into high/critical bugs
4. QUICK WINS — Low-hanging fruit that should be tested immediately
5. RECOMMENDED NEXT STEPS — What manual testing to do next

Recon summary:
{data}""",
}


class LLMAnalyzer:
    """Sends recon output to a local Ollama instance for AI analysis."""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434",
                 console=None):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.console = console
        self._available = None

    # ── Check Ollama is running ───────────────────────────────
    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                models = [m["name"].split(":")[0] for m in data.get("models", [])]
                if self.model not in models:
                    self._print(f"[yellow][!][/yellow] Model '[bold]{self.model}[/bold]' not found in Ollama.")
                    self._print(f"    Run: [cyan]ollama pull {self.model}[/cyan]")
                    self._print(f"    Available: {', '.join(models) if models else 'none'}")
                    self._available = False
                else:
                    self._available = True
        except Exception:
            self._available = False
            self._print("[red][✗][/red] Ollama not running. Start it with: [cyan]ollama serve[/cyan]")
            self._print("    Install: [cyan]https://ollama.com/download[/cyan]")
        return self._available

    # ── Send a single prompt to Ollama ───────────────────────
    def ask(self, prompt: str, context_label: str = "") -> Optional[str]:
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,      # lower = more focused/consistent
                "num_predict": 2048,     # max tokens in response
            }
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = json.loads(resp.read())
                return data.get("response", "").strip()
        except urllib.error.URLError as e:
            self._print(f"[red][✗][/red] Ollama request failed ({context_label}): {e}")
            return None
        except Exception as e:
            self._print(f"[red][✗][/red] LLM error ({context_label}): {e}")
            return None

    # ── Read a file safely, truncate if huge ─────────────────
    def _read(self, path: Path, max_lines: int = 200) -> Optional[str]:
        if not path.exists():
            return None
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        if not lines:
            return None
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            lines.append(f"... (truncated to {max_lines} lines for LLM context)")
        return "\n".join(lines)

    def _print(self, msg: str):
        if self.console:
            self.console.print(msg)
        else:
            print(msg)

    # ── Main analysis runner ──────────────────────────────────
    def run(self, scan_dir: Path, domain: str):
        from rich.rule import Rule
        from rich.panel import Panel
        from rich.markdown import Markdown

        self._print(Rule("[bold cyan]PHASE 9 — LLM Analysis (Ollama)[/bold cyan]"))
        self._print(f"[green][+][/green] Model: [bold]{self.model}[/bold]  |  API: {self.base_url}")

        if not self.is_available():
            self._print("\n[yellow]Tip:[/yellow] Skipping LLM analysis. Fix the above and re-run with --llm-analyze")
            return

        llm_dir = scan_dir / "llm_analysis"
        llm_dir.mkdir(exist_ok=True)

        analyses = []

        # ── Define what to analyse ────────────────────────────
        tasks = [
            ("subdomains", scan_dir / "subdomains" / "all_subdomains.txt", 150),
            ("endpoints",  scan_dir / "urls" / "interesting_endpoints.txt", 100),
            ("secrets",    scan_dir / "js" / "potential_secrets.txt", 80),
            ("nuclei",     scan_dir / "nuclei" / "findings.txt", 100),
            ("js_endpoints", scan_dir / "js" / "js_endpoints.txt", 100),
        ]

        for analysis_type, data_file, max_lines in tasks:
            data = self._read(data_file, max_lines)
            if not data:
                self._print(f"[dim]  – {analysis_type}: no data, skipping[/dim]")
                continue

            self._print(f"[cyan]  → Analysing {analysis_type}...[/cyan]", )

            prompt = PROMPTS[analysis_type].format(domain=domain, data=data)
            response = self.ask(prompt, context_label=analysis_type)

            if response:
                out_file = llm_dir / f"{analysis_type}.md"
                out_file.write_text(f"# LLM Analysis — {analysis_type.title()} ({domain})\n\n{response}\n")
                self._print(f"[green]  ✓[/green] {analysis_type} → {out_file.name}")
                analyses.append((analysis_type, response))
            else:
                self._print(f"[yellow]  ![/yellow] {analysis_type} — no response from LLM")

        # ── Final summary prompt combining all findings ────────
        if analyses:
            self._print(f"\n[cyan]  → Generating combined triage summary...[/cyan]")
            combined = "\n\n".join([f"=== {t.upper()} ===\n{r[:500]}" for t, r in analyses])
            summary_prompt = PROMPTS["summary"].format(domain=domain, data=combined)
            summary = self.ask(summary_prompt, context_label="summary")

            if summary:
                summary_file = llm_dir / "TRIAGE_SUMMARY.md"
                summary_file.write_text(
                    f"# Sayad LLM Triage Summary — {domain}\n"
                    f"**Model:** {self.model}\n\n"
                    f"---\n\n{summary}\n"
                )
                self._print(f"\n[bold green]  ✓ Triage summary → {summary_file}[/bold green]")

                # Print the summary in terminal too
                self._print("\n")
                if self.console:
                    self.console.print(Panel(
                        Markdown(summary[:2000]),
                        title=f"[bold]LLM Triage Summary — {domain}[/bold]",
                        border_style="green"
                    ))

        self._print(f"\n[green][+][/green] All LLM analyses saved → [cyan]{llm_dir}[/cyan]")
        self._print(f"[yellow]Tip:[/yellow] Feed [cyan]TRIAGE_SUMMARY.md[/cyan] to your bug bounty report workflow.")