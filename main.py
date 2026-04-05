#!/usr/bin/env python3
import asyncio
import aiohttp
import argparse
import json
import sys
import os
import re
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

load_dotenv()

console = Console()

VT_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_KEY  = os.getenv("SHODAN_API_KEY", "")


# ── Helpers ──────────────────────────────────────────────────────────────────

def is_ip(value: str) -> bool:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, value))


def score_color(score: int) -> str:
    if score >= 70:
        return "bold red"
    elif score >= 40:
        return "bold yellow"
    else:
        return "bold green"


# ── API Calls ─────────────────────────────────────────────────────────────────

async def query_virustotal(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
    if not VT_KEY:
        return {"error": "No API key configured"}
    try:
        endpoint = "ip_addresses" if ioc_type == "ip" else "domains"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
        headers = {"x-apikey": VT_KEY}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total      = sum(stats.values()) or 1

                # Per-engine detections — only flagged ones
                engine_results = attrs.get("last_analysis_results", {})
                flagged_engines = [
                    f"{name} ({info.get('result', '?')})"
                    for name, info in engine_results.items()
                    if info.get("category") in ("malicious", "suspicious")
                ]

                # Timestamps
                from datetime import timezone
                last_analysis_ts = attrs.get("last_analysis_date")
                last_analysis = (
                    datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    if last_analysis_ts else "N/A"
                )

                return {
                    "malicious":       malicious,
                    "suspicious":      suspicious,
                    "total_engines":   total,
                    "reputation":      attrs.get("reputation", 0),
                    "raw_score":       round(((malicious + suspicious) / total) * 100, 1),
                    "asn":             attrs.get("asn", "N/A"),
                    "as_owner":        attrs.get("as_owner", "N/A"),
                    "country":         attrs.get("country", "N/A"),
                    "continent":       attrs.get("continent", "N/A"),
                    "network":         attrs.get("network", "N/A"),
                    "tags":            attrs.get("tags", []),
                    "votes":           attrs.get("total_votes", {}),
                    "last_analysis":   last_analysis,
                    "flagged_engines": flagged_engines,
                }
            else:
                return {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"error": str(e)}


async def query_abuseipdb(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
    if not ABUSE_KEY:
        return {"error": "No API key configured"}
    if ioc_type == "domain":
        return {"error": "AbuseIPDB only supports IP addresses"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_KEY, "Accept": "application/json", "Accept-Encoding": "gzip, deflate"}
        params  = {"ipAddress": ioc, "maxAgeInDays": "90"}
        async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json()
                d = data.get("data", {})
                return {
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                        "total_reports":          d.get("totalReports", 0),
                        "distinct_users":         d.get("numDistinctUsers", 0),
                        "last_reported":          d.get("lastReportedAt", "N/A"),
                        "country_code":           d.get("countryCode", "N/A"),
                        "isp":                    d.get("isp", "N/A"),
                        "domain":                 d.get("domain", "N/A"),
                        "is_tor":                 d.get("isTor", False),
                        "usage_type":             d.get("usageType", "N/A"),
                }
                
            else:
                return {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"error": str(e)}


async def query_shodan(session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
    if not SHODAN_KEY:
        return {"error": "No API key configured"}
    try:
        if ioc_type == "ip":
            url = f"https://api.shodan.io/shodan/host/{ioc}?key={SHODAN_KEY}"
        else:
            url = f"https://api.shodan.io/dns/resolve?hostnames={ioc}&key={SHODAN_KEY}"

        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if ioc_type == "ip":
                    ports = data.get("ports", [])
                    raw_vulns = data.get("vulns", [])
                    vulns = list(raw_vulns.keys()) if isinstance(raw_vulns, dict) else list(raw_vulns)
                    return {
                        "open_ports":  ports,
                        "port_count":  len(ports),
                        "vulns":       vulns,
                        "vuln_count":  len(vulns),
                        "org":         data.get("org", "N/A"),
                        "isp":         data.get("isp", "N/A"),
                        "asn":         data.get("asn", "N/A"),
                        "os":          data.get("os", "N/A"),
                        "country":     data.get("country_name", "N/A"),
                        "city":        data.get("city", "N/A"),
                        "hostnames":   data.get("hostnames", []),
                        "domains":     data.get("domains", []),
                        "tags":        data.get("tags", []),
                    }
                else:
                    resolved_ip = data.get(ioc, "N/A")
                    return {"resolved_ip": resolved_ip}
            else:
                return {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"error": str(e)}


# ── Display ───────────────────────────────────────────────────────────────────

def display_results(ioc: str, ioc_type: str, vt: dict, abuse: dict, shodan: dict, silent: bool = False):
    if silent:
        console.print(f"[dim]✓ {ioc} — enrichment complete[/dim]")
        return
    console.print()
    console.print(Panel(
        f"[bold white]IOC:[/bold white]  {ioc}\n"
        f"[bold white]Type:[/bold white] {ioc_type.upper()}\n"
        f"[bold white]Time:[/bold white] {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        title="[bold cyan]IOC Enrichment Report[/bold cyan]",
        border_style="cyan",
        expand=False,
    ))
    # VirusTotal
    vt_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    vt_table.add_column("Field", style="dim")
    vt_table.add_column("Value")
    if "error" in vt:
        vt_table.add_row("Status", f"[red]{vt['error']}[/red]")
    else:
        vt_table.add_row("Malicious / Suspicious", f"[red]{vt.get('malicious',0)}[/red] / [yellow]{vt.get('suspicious',0)}[/yellow]")
        vt_table.add_row("Total Engines",    str(vt.get("total_engines", "N/A")))
        vt_table.add_row("Detection Rate",   f"{vt.get('raw_score', 0)}%")
        vt_table.add_row("Reputation",       str(vt.get("reputation", "N/A")))
        vt_table.add_row("ASN",              f"{vt.get('asn', 'N/A')} ({vt.get('as_owner', 'N/A')})")
        vt_table.add_row("Country",          f"{vt.get('country', 'N/A')} / {vt.get('continent', 'N/A')}")
        vt_table.add_row("Network",          str(vt.get("network", "N/A")))
        vt_table.add_row("Last Analysis",    vt.get("last_analysis", "N/A"))
        votes = vt.get("votes", {})
        vt_table.add_row("Community Votes",  f"[red]malicious: {votes.get('malicious',0)}[/red]  harmless: {votes.get('harmless',0)}")
        tags = vt.get("tags", [])
        vt_table.add_row("Tags",             ", ".join(tags) if tags else "None")
        flagged = vt.get("flagged_engines", [])
        vt_table.add_row("Flagged By",       "\n".join(flagged[:10]) if flagged else "None")
    console.print(Panel(vt_table, title="[bold magenta]VirusTotal[/bold magenta]", border_style="magenta", expand=False))

    # AbuseIPDB
    ab_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    ab_table.add_column("Field", style="dim")
    ab_table.add_column("Value")
    if "error" in abuse:
        ab_table.add_row("Status", f"[red]{abuse['error']}[/red]")
    else:
        conf = abuse.get("abuse_confidence_score", 0)
        ab_table.add_row("Confidence Score", f"[{score_color(conf)}]{conf}%[/{score_color(conf)}]")
        ab_table.add_row("Total Reports",    str(abuse.get("total_reports", "N/A")))
        ab_table.add_row("Distinct Users",   str(abuse.get("distinct_users", "N/A")))
        ab_table.add_row("Last Reported",    abuse.get("last_reported", "N/A"))
        ab_table.add_row("Country",          abuse.get("country_code", "N/A"))
        ab_table.add_row("ISP",              abuse.get("isp", "N/A"))
        ab_table.add_row("Domain Name",      abuse.get("domain", "N/A"))
        ab_table.add_row("Usage Type",       abuse.get("usage_type", "N/A"))
        ab_table.add_row("Tor Exit Node",    "[red]Yes[/red]" if abuse.get("is_tor") else "No")
    console.print(Panel(ab_table, title="[bold blue]AbuseIPDB[/bold blue]", border_style="blue", expand=False))

    # Shodan
    sh_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    sh_table.add_column("Field", style="dim")
    sh_table.add_column("Value")
    if "error" in shodan:
        sh_table.add_row("Status", f"[red]{shodan['error']}[/red]")
    elif "resolved_ip" in shodan:
        sh_table.add_row("Resolved IP", shodan.get("resolved_ip", "N/A"))
    else:
        sh_table.add_row("Organization", shodan.get("org", "N/A"))
        sh_table.add_row("ISP",          shodan.get("isp", "N/A"))
        sh_table.add_row("ASN",          str(shodan.get("asn", "N/A")))
        sh_table.add_row("Country",      shodan.get("country", "N/A"))
        sh_table.add_row("City",         shodan.get("city", "N/A"))
        hostnames = shodan.get("hostnames", [])
        sh_table.add_row("Hostnames",    ", ".join(hostnames) if hostnames else "None")
        domains = shodan.get("domains", [])
        sh_table.add_row("Domains",      ", ".join(domains) if domains else "None")
        ports = shodan.get("open_ports", [])
        sh_table.add_row("Open Ports",   ", ".join(map(str, ports[:15])) + ("…" if len(ports) > 15 else "") or "None")
        vulns = shodan.get("vulns", [])
        sh_table.add_row("CVEs Found",   f"[red]{len(vulns)}[/red]: " + ", ".join(vulns[:]) if vulns else "None")
        sh_table.add_row("Tags",         ", ".join(shodan.get("tags", [])) or "None")
    console.print(Panel(sh_table, title="[bold yellow]Shodan[/bold yellow]", border_style="yellow", expand=False))


# ── JSON Export ───────────────────────────────────────────────────────────────

def export_json(ioc: str, ioc_type: str, vt: dict, abuse: dict, shodan: dict,  output_path: str):
    payload = {
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "ioc":              ioc,
        "ioc_type":         ioc_type,
        "virustotal":       vt,
        "abuseipdb":        abuse,
        "shodan":           shodan,
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    console.print(f"\n[dim]JSON report saved → {output_path}[/dim]")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Async IOC Enrichment Tool — VirusTotal + AbuseIPDB + Shodan"
    )
    parser.add_argument("ioc",    help="IP address or domain name to investigate", nargs="?")
    parser.add_argument("--file", help="Path to file with one IOC per line", metavar="FILE")
    parser.add_argument("--json", help="Export results to this JSON file path", metavar="FILE")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output, useful for bulk scanning or JSON export")

    args = parser.parse_args()

    iocs = []
    if args.file:
        with open(args.file, "r") as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.ioc:
        iocs = [args.ioc.strip()]
    else:
        parser.error("Provide an IOC or use --file")

    async with aiohttp.ClientSession() as session:
        for ioc in iocs:
            ioc_type = "ip" if is_ip(ioc) else "domain"
            console.print(f"\n[cyan]Querying intelligence sources for[/cyan] [bold]{ioc}[/bold] [dim]({ioc_type})[/dim]...")

            vt, abuse, shodan = await asyncio.gather(
                query_virustotal(session, ioc, ioc_type),
                query_abuseipdb(session, ioc, ioc_type),
                query_shodan(session, ioc, ioc_type),
            )

            display_results(ioc, ioc_type, vt, abuse, shodan, silent=args.silent)

            if args.json:
                base, ext = os.path.splitext(args.json)
                out_path = f"{base}_{ioc.replace('.', '_')}{ext}" if len(iocs) > 1 else args.json
                export_json(ioc, ioc_type, vt, abuse, shodan, out_path)


if __name__ == "__main__":
    asyncio.run(main())
