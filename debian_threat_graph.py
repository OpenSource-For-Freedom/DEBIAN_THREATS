# File: debian_threat_graph.py

import os
import json
import requests
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from datetime import datetime
from collections import Counter

CACHE_FILE = "threat_cache.json"
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/search/pulses"
HEADERS = {"X-OTX-API-KEY": OTX_KEY}
PARAMS = {"q": "debian vulnerability cve", "page": 1}
LOGO_PATH = "HARDN (1).png"
LOGO_URL = "HARDN%20(1).png"  # relative path


def fetch_threats():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            cached = json.load(f)
            return cached

    response = requests.get(OTX_URL, headers=HEADERS, params=PARAMS)
    response.raise_for_status()
    results = response.json().get("results", [])

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


def extract_year_counts(threats):
    years = []
    for threat in threats:
        created = threat.get("created")
        if created:
            try:
                year = datetime.fromisoformat(created).year
                years.append(year)
            except Exception:
                continue
    return Counter(years)


def add_logo_to_plot(ax, fig):
    if os.path.exists(LOGO_PATH):
        logo = mpimg.imread(LOGO_PATH)
        fig_width, fig_height = fig.get_size_inches() * fig.dpi
        logo_width = 120
        logo_height = 60
        x_offset = int(fig_width - logo_width - 10)
        y_offset = int(fig_height - logo_height - 10)
        fig.figimage(logo, xo=x_offset, yo=y_offset, alpha=0.25, zorder=10)


def plot_main_graph(year_counter):
    full_years = list(range(2005, 2026))
    counts = [year_counter.get(y, 0) for y in full_years]
    max_count = max(counts)

    colors = ["red" if c == max_count else "skyblue" for c in counts]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(full_years, counts, color=colors)
    ax.set_title("Debian Threats by Year (2005–2025)")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of Threats")

    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(count), ha='center', va='bottom')

    ax.legend([bars[0]], [f"Peak Year: {full_years[counts.index(max_count)]}"], loc='upper right')
    add_logo_to_plot(ax, fig)
    plt.tight_layout()
    plt.savefig("threats_by_year.png")
    plt.close()


def plot_trend_graph(year_counter):
    full_years = list(range(2005, 2026))
    counts = [year_counter.get(y, 0) for y in full_years]
    avg_count = sum(counts) / len(full_years) if full_years else 0

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(full_years, counts, marker='o', linestyle='-', color='green', label='Threat Trend')
    ax.axhline(y=avg_count, color='orange', linestyle='--', label=f'Average: {avg_count:.1f}')
    ax.set_title("Debian Threat Trend Indicator")
    ax.set_xlabel("Year")
    ax.set_ylabel("Threat Count")
    ax.legend()
    ax.grid(True)
    add_logo_to_plot(ax, fig)
    plt.tight_layout()
    plt.savefig("threat_trend_line.png")
    plt.close()


def write_to_readme(table_blocks):
    with open("README.md", "w", encoding="utf-8") as f:
        f.write("# Debian Threats Report\n\n")
        f.write(f"_Last updated: {datetime.utcnow().isoformat()} UTC_\n\n")
        f.write(f'<p align="center"><img src="{LOGO_URL}" width="180" alt="Project Logo"></p>\n\n')
        f.write("![Debian Threats by Year](threats_by_year.png)\n\n")
        f.write("![Threat Trend](threat_trend_line.png)\n\n")
        f.write("## Threat Table\n\n")
        for block in table_blocks:
            f.write(block + "\n\n")


def generate_tables(threats, per_page=5):
    table_md_blocks = []
    for i in range(0, len(threats), per_page):
        chunk = threats[i:i + per_page]
        table_md = ["| Name | Created | Description |", "|------|---------|-------------|"]
        for threat in chunk:
            name = threat.get("name", "Unknown").replace("|", "-")
            created = threat.get("created", "N/A")
            description = threat.get("description", "No description").replace("|", "-").strip().replace("\n", " ")[:100] + '...'
            year = created[:4] if created and len(created) >= 4 else ""
            link = f"https://otx.alienvault.com/pulses/search?q=debian%20{year}" if year else ""
            if link:
                table_md.append(f"| [{name}]({link}) | {created} | {description} |")
            else:
                table_md.append(f"| {name} | {created} | {description} |")
        table_md_blocks.append("\n".join(table_md))
    return table_md_blocks


def main():
    if not OTX_KEY:
        raise EnvironmentError("OTX_KEY environment variable is not set")

    threats = fetch_threats()
    if not threats:
        print("No threats retrieved.")
        return

    year_data = extract_year_counts(threats)
    plot_main_graph(year_data)
    plot_trend_graph(year_data)
    tables = generate_tables(threats)
    write_to_readme(tables)
    print("README.md updated with Debian threat graphs and tables.")


if __name__ == "__main__":
    main()
