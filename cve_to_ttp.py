#!/usr/bin/env python3
"""
cve_to_ttp.py - Translate CVEs from a host into MITRE ATT&CK TTPs

Mapping chain:
    CVE ──► NVD API ──► CWE IDs
    CWE ──► MITRE CAPEC XML ──► CAPEC IDs
    CAPEC ──► MITRE ATT&CK STIX ──► Techniques (TTPs)

Optional paid enrichment:
    CVE ──► RST Cloud Threat Intelligence API ──► TTPs + threat context

Usage:
    # From a list of CVEs passed directly
    python3 cve_to_ttp.py CVE-2021-44228 CVE-2023-23397

    # From a file (one CVE per line, or comma-separated)
    python3 cve_to_ttp.py -f cves.txt

    # With RST Cloud enrichment
    python3 cve_to_ttp.py -f cves.txt --rst-key <your_api_key>

    # JSON output
    python3 cve_to_ttp.py CVE-2021-44228 --json
"""

import argparse
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
RST_CLOUD_BASE = "https://api.rstcloud.net/v1"

# Local cache directory (avoids re-downloading MITRE data on every run)
CACHE_DIR = Path(os.path.expanduser("~/.cache/cve_to_ttp"))
CAPEC_CACHE = CACHE_DIR / "capec_latest.xml"
ATTACK_CACHE = CACHE_DIR / "enterprise-attack.json"
CACHE_MAX_AGE_DAYS = 7  # re-download MITRE data weekly

# NVD rate limits: 5 req/30s without API key, 50 req/30s with key
NVD_RATE_DELAY = 6.5  # seconds between NVD calls (conservative, no key)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cache_is_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age_days = (time.time() - path.stat().st_mtime) / 86400
    return age_days < CACHE_MAX_AGE_DAYS


def _download(url: str, dest: Path, label: str) -> None:
    print(f"[*] Downloading {label} ...", file=sys.stderr)
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, timeout=120, stream=True)
    r.raise_for_status()
    with open(dest, "wb") as fh:
        for chunk in r.iter_content(chunk_size=1 << 16):
            fh.write(chunk)
    print(f"[+] Saved to {dest}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 1 – Query NVD for CVE details (CWE IDs + metadata)
# ---------------------------------------------------------------------------

def fetch_nvd_cve(cve_id: str, nvd_key: str | None = None) -> dict:
    """Return raw NVD CVE item dict, or {} on failure."""
    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        r = requests.get(
            NVD_API_BASE,
            params={"cveId": cve_id},
            headers=headers,
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        items = data.get("vulnerabilities", [])
        return items[0]["cve"] if items else {}
    except Exception as exc:
        print(f"[!] NVD lookup failed for {cve_id}: {exc}", file=sys.stderr)
        return {}


def extract_cwes(nvd_cve: dict) -> list[str]:
    """Pull CWE IDs out of an NVD CVE object."""
    cwes = []
    for weakness in nvd_cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if re.match(r"CWE-\d+", val):
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


def extract_cvss(nvd_cve: dict) -> dict:
    """Return highest available CVSS score + vector."""
    metrics = nvd_cve.get("metrics", {})
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": data.get("version", version[-2:]),
                "score": data.get("baseScore"),
                "severity": entries[0].get("baseSeverity")
                or data.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return {}


# ---------------------------------------------------------------------------
# Step 2 – Build CWE → CAPEC mapping from MITRE CAPEC XML
# ---------------------------------------------------------------------------

def load_cwe_to_capec() -> dict[str, list[str]]:
    """
    Parse CAPEC XML and return {cwe_id: [capec_id, ...]} mapping.
    Each CAPEC attack pattern lists related CWEs in its XML.
    """
    if not _cache_is_fresh(CAPEC_CACHE):
        _download(CAPEC_XML_URL, CAPEC_CACHE, "MITRE CAPEC XML")

    print("[*] Parsing CAPEC data ...", file=sys.stderr)
    tree = ET.parse(CAPEC_CACHE)
    root = tree.getroot()

    # CAPEC XML uses a namespace
    ns_match = re.match(r"\{.*\}", root.tag)
    ns = ns_match.group(0) if ns_match else ""

    cwe_to_capec: dict[str, list[str]] = {}

    for pattern in root.iter(f"{ns}Attack_Pattern"):
        capec_id = "CAPEC-" + pattern.get("ID", "")
        related_weaknesses = pattern.find(f"{ns}Related_Weaknesses")
        if related_weaknesses is None:
            continue
        for weakness in related_weaknesses.iter(f"{ns}Related_Weakness"):
            cwe_id = "CWE-" + weakness.get("CWE_ID", "")
            cwe_to_capec.setdefault(cwe_id, []).append(capec_id)

    return cwe_to_capec


# ---------------------------------------------------------------------------
# Step 3 – Build CAPEC → ATT&CK Technique mapping from MITRE ATT&CK STIX
# ---------------------------------------------------------------------------

def load_capec_to_techniques() -> dict[str, list[dict]]:
    """
    Parse ATT&CK enterprise STIX bundle and return
    {capec_id: [{id, name, url, tactic}, ...]} mapping.
    """
    if not _cache_is_fresh(ATTACK_CACHE):
        _download(ATTACK_STIX_URL, ATTACK_CACHE, "MITRE ATT&CK STIX")

    print("[*] Parsing ATT&CK STIX data ...", file=sys.stderr)
    with open(ATTACK_CACHE) as fh:
        bundle = json.load(fh)

    # Build tactic phase lookup from x-mitre-tactic objects
    tactic_lookup: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            tactic_lookup[short] = name

    capec_to_techniques: dict[str, list[dict]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Extract CAPEC references from external_references
        capec_ids = [
            ref["external_id"]
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "capec"
        ]
        if not capec_ids:
            continue

        # ATT&CK technique ID + URL
        technique_id = ""
        technique_url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                technique_url = ref.get("url", "")
                break

        # Tactic names from kill chain phases
        tactics = [
            tactic_lookup.get(phase["phase_name"], phase["phase_name"])
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        technique = {
            "id": technique_id,
            "name": obj.get("name", ""),
            "url": technique_url,
            "tactics": tactics,
            "description": obj.get("description", "").split("\n")[0][:200],
        }

        for capec_id in capec_ids:
            # Normalise "CAPEC-123" format
            normalised = capec_id if capec_id.startswith("CAPEC-") else f"CAPEC-{capec_id}"
            capec_to_techniques.setdefault(normalised, []).append(technique)

    return capec_to_techniques


# ---------------------------------------------------------------------------
# Step 4 (optional) – RST Cloud enrichment
# ---------------------------------------------------------------------------

def fetch_rst_cloud(cve_id: str, api_key: str) -> dict:
    """
    Query RST Cloud Threat Intelligence API for a CVE.
    Returns dict with keys: ttps, threat_actors, malware_families, raw.
    RST Cloud API docs: https://www.rstcloud.com/api/
    """
    try:
        r = requests.get(
            f"{RST_CLOUD_BASE}/ioc",
            params={"value": cve_id, "type": "cve"},
            headers={"X-Api-Key": api_key},
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()

        # RST Cloud returns a "indicators" or "data" list — normalise it
        indicators = data.get("data") or data.get("indicators") or []
        entry = indicators[0] if indicators else {}

        # Extract ATT&CK TTPs if RST Cloud includes them
        ttps = []
        for ttp in entry.get("attack", {}).get("techniques", []):
            ttps.append({
                "id": ttp.get("id", ""),
                "name": ttp.get("name", ""),
                "tactics": ttp.get("tactics", []),
                "source": "rst_cloud",
            })

        return {
            "ttps": ttps,
            "threat_actors": [a.get("name") for a in entry.get("threat_actors", [])],
            "malware_families": [m.get("name") for m in entry.get("malware", [])],
            "rst_score": entry.get("score"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "raw": entry,
        }

    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return {}  # CVE not in RST Cloud — not an error
        print(f"[!] RST Cloud lookup failed for {cve_id}: {exc}", file=sys.stderr)
        return {}
    except Exception as exc:
        print(f"[!] RST Cloud lookup failed for {cve_id}: {exc}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def cve_to_ttps(
    cve_id: str,
    cwe_to_capec: dict,
    capec_to_techniques: dict,
    nvd_key: str | None = None,
    rst_key: str | None = None,
    nvd_delay: float = NVD_RATE_DELAY,
) -> dict:
    """
    Full pipeline for a single CVE ID.
    Returns a structured result dict.
    """
    result = {
        "cve": cve_id,
        "description": "",
        "cvss": {},
        "cwes": [],
        "capecs": [],
        "ttps": [],          # from CWE→CAPEC→ATT&CK chain
        "rst_cloud": None,   # populated if rst_key provided
        "errors": [],
    }

    # 1. NVD lookup
    nvd_data = fetch_nvd_cve(cve_id, nvd_key)
    if not nvd_data:
        result["errors"].append("NVD returned no data")
    else:
        descriptions = nvd_data.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                result["description"] = d.get("value", "")
                break
        result["cvss"] = extract_cvss(nvd_data)
        result["cwes"] = extract_cwes(nvd_data)

    # 2. CWE → CAPEC
    seen_capecs: set[str] = set()
    for cwe in result["cwes"]:
        for capec in cwe_to_capec.get(cwe, []):
            if capec not in seen_capecs:
                result["capecs"].append(capec)
                seen_capecs.add(capec)

    # 3. CAPEC → ATT&CK techniques
    seen_techniques: set[str] = set()
    for capec in result["capecs"]:
        for technique in capec_to_techniques.get(capec, []):
            tid = technique["id"]
            if tid not in seen_techniques:
                result["ttps"].append({**technique, "source": "mitre_chain", "via_capec": capec})
                seen_techniques.add(tid)

    # 4. RST Cloud enrichment (optional)
    if rst_key:
        rst_data = fetch_rst_cloud(cve_id, rst_key)
        if rst_data:
            result["rst_cloud"] = rst_data
            # Merge RST Cloud TTPs that aren't already in the list
            for ttp in rst_data.get("ttps", []):
                if ttp["id"] not in seen_techniques:
                    result["ttps"].append(ttp)
                    seen_techniques.add(ttp["id"])

    time.sleep(nvd_delay)
    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_table(results: list[dict]) -> None:
    """Human-readable table output."""
    sep = "─" * 80
    for r in results:
        print(f"\n{sep}")
        print(f"  CVE : {r['cve']}")
        if r["description"]:
            desc = r["description"][:120] + ("..." if len(r["description"]) > 120 else "")
            print(f"  Desc: {desc}")
        if r["cvss"]:
            c = r["cvss"]
            print(f"  CVSS: {c.get('score')} ({c.get('severity')})  [{c.get('version')}]")
        print(f"  CWE : {', '.join(r['cwes']) or 'none'}")
        print(f"  CAPEC: {', '.join(r['capecs']) or 'none'}")

        if not r["ttps"]:
            print("  TTPs: none mapped")
        else:
            print(f"  TTPs ({len(r['ttps'])}):")
            for t in r["ttps"]:
                tactics = " / ".join(t.get("tactics", [])) or "—"
                source_tag = f"[{t.get('source', '')}]" if t.get("source") != "mitre_chain" else ""
                capec_tag = f"via {t.get('via_capec', '')}" if t.get("via_capec") else ""
                tags = " ".join(filter(None, [source_tag, capec_tag]))
                print(f"    • {t['id']:12s} {t['name']}")
                print(f"      Tactic : {tactics}")
                if tags:
                    print(f"      Tags   : {tags}")
                if t.get("description"):
                    print(f"      Desc   : {t['description'][:100]}...")

        if r.get("rst_cloud"):
            rst = r["rst_cloud"]
            if rst.get("threat_actors"):
                print(f"  RST Actors  : {', '.join(rst['threat_actors'])}")
            if rst.get("malware_families"):
                print(f"  RST Malware : {', '.join(rst['malware_families'])}")
            if rst.get("rst_score") is not None:
                print(f"  RST Score   : {rst['rst_score']}")

        if r["errors"]:
            for e in r["errors"]:
                print(f"  [!] {e}")

    print(f"\n{sep}")
    print(f"  Total CVEs: {len(results)}")
    total_ttps = sum(len(r['ttps']) for r in results)
    unique_ttps = len({t['id'] for r in results for t in r['ttps']})
    print(f"  Total TTPs: {total_ttps} ({unique_ttps} unique)")
    print(sep)


def print_summary_matrix(results: list[dict]) -> None:
    """Compact tactic matrix across all CVEs."""
    from collections import defaultdict
    tactic_map: dict[str, list[str]] = defaultdict(list)
    for r in results:
        for t in r["ttps"]:
            for tactic in t.get("tactics", []):
                key = f"{t['id']} – {t['name']}"
                if key not in tactic_map[tactic]:
                    tactic_map[tactic].append(key)

    if not tactic_map:
        return

    print("\n── ATT&CK Tactic Matrix ──────────────────────────────────────")
    for tactic in sorted(tactic_map):
        print(f"\n  [{tactic.upper()}]")
        for tech in sorted(tactic_map[tactic]):
            print(f"    • {tech}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_cves_from_file(path: str) -> list[str]:
    """Read CVEs from a file: one per line or comma-separated."""
    cves = []
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    with open(path) as fh:
        for line in fh:
            cves.extend(m.upper() for m in cve_pattern.findall(line))
    return list(dict.fromkeys(cves))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map CVEs to MITRE ATT&CK TTPs via CWE→CAPEC→ATT&CK chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "cves",
        nargs="*",
        metavar="CVE-XXXX-XXXXX",
        help="One or more CVE IDs",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="File containing CVE IDs (one per line or comma-separated)",
    )
    parser.add_argument(
        "--nvd-key",
        metavar="KEY",
        default=os.environ.get("NVD_API_KEY"),
        help="NVD API key (or set NVD_API_KEY env var). Increases rate limit.",
    )
    parser.add_argument(
        "--rst-key",
        metavar="KEY",
        default=os.environ.get("RST_CLOUD_API_KEY"),
        help="RST Cloud API key (or set RST_CLOUD_API_KEY env var).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of the human-readable table",
    )
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="Print a tactic matrix summary after the main output",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Force re-download of MITRE CAPEC and ATT&CK data",
    )
    args = parser.parse_args()

    # Collect CVE IDs
    cve_ids: list[str] = []
    if args.file:
        cve_ids.extend(parse_cves_from_file(args.file))
    for cve in args.cves:
        normalised = cve.upper().strip()
        if re.match(r"CVE-\d{4}-\d{4,}$", normalised):
            cve_ids.append(normalised)
        else:
            print(f"[!] Skipping invalid CVE ID: {cve}", file=sys.stderr)
    cve_ids = list(dict.fromkeys(cve_ids))  # deduplicate

    if not cve_ids:
        parser.print_help()
        sys.exit(1)

    # Optionally force cache refresh
    if args.refresh_cache:
        CAPEC_CACHE.unlink(missing_ok=True)
        ATTACK_CACHE.unlink(missing_ok=True)

    # Load MITRE reference data once
    cwe_to_capec = load_cwe_to_capec()
    capec_to_techniques = load_capec_to_techniques()

    # Rate limit info
    delay = NVD_RATE_DELAY if not args.nvd_key else 1.0
    if not args.nvd_key:
        print(
            "[*] No NVD API key set — using conservative 6.5s delay between requests.\n"
            "    Set NVD_API_KEY env var or pass --nvd-key to increase throughput.",
            file=sys.stderr,
        )

    # Process each CVE
    print(f"[*] Processing {len(cve_ids)} CVE(s) ...\n", file=sys.stderr)
    results = []
    for cve_id in cve_ids:
        print(f"[*] {cve_id}", file=sys.stderr)
        result = cve_to_ttps(
            cve_id,
            cwe_to_capec,
            capec_to_techniques,
            nvd_key=args.nvd_key,
            rst_key=args.rst_key,
            nvd_delay=delay,
        )
        results.append(result)

    # Output
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_table(results)
        if args.matrix:
            print_summary_matrix(results)


if __name__ == "__main__":
    main()
