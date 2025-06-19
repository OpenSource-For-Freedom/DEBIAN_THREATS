# File: debian_threat_graph.py

import os
import json
import requests
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from datetime import datetime, timedelta
from collections import Counter


CACHE_FILE     = "threat_cache.json"
CACHE_TTL_DAYS = int(os.getenv("CACHE_TTL_DAYS", "1"))
OTX_KEY        = os.getenv("OTX_KEY")
VULN_KEY       = os.getenv("VULN_KEY")
CVSS_MIN       = float(os.getenv("CVSS_MIN", "0"))
DATE_FROM      = os.getenv("DATE_FROM")  # e.g. '2005-01-01'
DATE_TO        = os.getenv("DATE_TO")    # e.g. '2025-12-31'
OTX_PAGES      = int(os.getenv("OTX_PAGES", "3"))
VULN_SIZE      = int(os.getenv("VULN_SIZE", "20"))


OTX_URL       = "https://otx.alienvault.com/api/v1/search/pulses"
VULNERS_URL   = "https://vulners.com/api/v3/search/lucene/"
HEADERS_OTX   = {"X-OTX-API-KEY": OTX_KEY}
PARAMS_OTX    = {"q": "Linux Kernel"}
LOGO_PATH     = "HARDN (1).png"
LOGO_URL      = "HARDN%20(1).png"


def parse_date(s):
    return datetime.fromisoformat(s[:10]) if s else None

def in_date_range(s):
    dt = parse_date(s)
    if DATE_FROM and dt < datetime.fromisoformat(DATE_FROM): return False
    if DATE_TO   and dt > datetime.fromisoformat(DATE_TO):   return False
    return True

def cache_is_valid(path):
    if not os.path.exists(path):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(path))
    return datetime.utcnow() - mtime < timedelta(days=CACHE_TTL_DAYS)


def fetch_otx_threats():
    otx_results = []
    print(f"[DEBUG] Fetching OTX pages 1–{OTX_PAGES}…")
    for page in range(1, OTX_PAGES + 1):
        resp = requests.get(OTX_URL, headers=HEADERS_OTX,
                            params={**PARAMS_OTX, "page": page})
        resp.raise_for_status()
        page_data = resp.json().get("results", [])
        print(f"[DEBUG]  • OTX page {page}: {len(page_data)} items")
        if not page_data:
            break
        otx_results.extend(page_data)
    print(f"[DEBUG] Total OTX items fetched: {len(otx_results)}")
    return otx_results

def fetch_vulners_threats():
    if not VULN_KEY:
        print("[DEBUG] No VULN_KEY set → skipping Vulners")
        return []
    payload = {"query": "Linux Kernel", "apiKey": VULN_KEY, "size": VULN_SIZE}
    print(f"[DEBUG] Querying Vulners (size={VULN_SIZE})…")
    resp = requests.post(VULNERS_URL, json=payload)
    resp.raise_for_status()
    docs = resp.json().get("data", {}).get("documents", [])
    print(f"[DEBUG] Vulners returned: {len(docs)} documents")
    parsed = []
    for d in docs:
        parsed.append({
            "name": d.get("title"),
            "created": d.get("published"),
            "description": d.get("bulletin", ""),
            "cvss": d.get("cvss", {}).get("score", 0)
        })
    return parsed

def fetch_threats():
    if cache_is_valid(CACHE_FILE):
        print(f"[DEBUG] Using cache (TTL {CACHE_TTL_DAYS} days)")
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    otx   = fetch_otx_threats()
    vuln  = fetch_vulners_threats()
    combined = []
    for t in (otx + vuln):
        c = t.get("created")
        if not in_date_range(c):
            continue
        if t.get("cvss", 0) < CVSS_MIN:
            continue
        combined.append(t)

    print(f"[DEBUG] After filter: OTX={len(otx)}, Vulners={len(vuln)}, Combined={len(combined)}")
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    return combined

def add_logo_to_plot(ax, fig):
    if os.path.exists(LOGO_PATH):
        logo = mpimg.imread(LOGO_PATH)
        fw, fh = fig.get_size_inches() * fig.dpi
        lw, lh = 120, 60
        fig.figimage(logo, xo=int(fw - lw - 10), yo=int(fh - lh - 10), alpha=0.25)

def extract_year_counts(threats):
    years = [parse_date(t["created"]).year for t in threats if t.get("created")]
    return Counter(years)

def plot_main_graph(year_counter):
    years = list(range(2005, 2026))
    counts = [year_counter.get(y, 0) for y in years]
    mx = max(counts)
    colors = ["red" if c == mx else "skyblue" for c in counts]
    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(years, counts, color=colors)
    ax.set(title="Linux Kernel Threats by Year", xlabel="Year", ylabel="Count")
    for bar, c in zip(bars, counts):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height(), str(c), ha='center', va='bottom')
    ax.legend([bars[0]], [f"Peak: {years[counts.index(mx)]}"], loc='upper right')
    add_logo_to_plot(ax, fig)
    plt.tight_layout()
    plt.savefig("threats_by_year.png")
    plt.close()

def plot_trend_graph(year_counter):
    years = list(range(2005, 2026))
    counts = [year_counter.get(y, 0) for y in years]
    avg = sum(counts)/len(counts)
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(years, counts, '-o', color='green', label='Trend')
    ax.axhline(avg, color='orange', linestyle='--', label=f'Avg {avg:.1f}')
    ax.set(title="Trend Indicator", xlabel="Year", ylabel="Count")
    ax.legend(); ax.grid(True)
    add_logo_to_plot(ax, fig)
    plt.tight_layout()
    plt.savefig("threat_trend_line.png")
    plt.close()

def generate_tables(threats, per_page=5):
    blocks = []
    for i in range(0, len(threats), per_page):
        chunk = threats[i:i+per_page]
        md = ["|Name|Created|Desc|CVSS|", "|---|---|---|---|"]
        for t in chunk:
            name = t.get("name","-").replace('|','-')
            created = t.get("created","")
            desc = t.get("description"," ").replace('|','-').replace('\n',' ')[:80]+'...'
            cvss = t.get("cvss", 0)
            md.append(f"|{name}|{created}|{desc}|{cvss}|")
        blocks.append("\n".join(md))
    return blocks

def write_to_readme(tabs):
    with open("README.md","w", encoding="utf-8") as f:
        f.write(f"# Debian Threat Database\n\n_Last updated: {datetime.utcnow().isoformat()}_\n\n")
        f.write(f'<p align="center"><img src="{LOGO_URL}" width="180"></p>\n\n')
        f.write("![Threats](threats_by_year.png)\n\n![Trend](threat_trend_line.png)\n\n## Data Table\n\n")
        for b in tabs:
            f.write(b+"\n\n")

def main():
    print(f"[CONFIG] CVSS_MIN={CVSS_MIN}, DATE_FROM={DATE_FROM}, DATE_TO={DATE_TO}, CACHE_TTL_DAYS={CACHE_TTL_DAYS}")
    if not (OTX_KEY or VULN_KEY):
        raise EnvironmentError("Set at least one of OTX_KEY or VULN_KEY in env")
    threats = fetch_threats()
    data = extract_year_counts(threats)
    plot_main_graph(data)
    plot_trend_graph(data)
    tables = generate_tables(threats)
    write_to_readme(tables)
    print("[DONE] README.md updated with filtered data.")

if __name__ == '__main__':
    main()
