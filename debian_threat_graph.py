# File: debian_threat_graph.py

import os
import requests
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.table import Table
from datetime import datetime


# OTX API
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/search/pulses"
HEADERS = {"X-OTX-API-KEY": OTX_KEY}
PARAMS = {"q": "debian vulnerability cve", "page": 1}

def fetch_threats():
    response = requests.get(OTX_URL, headers=HEADERS, params=PARAMS)
    response.raise_for_status()
    return response.json().get("results", [])

def generate_tables(threats, per_page=5):
    tables = []
    for i in range(0, len(threats), per_page):
        chunk = threats[i:i + per_page]
        fig, ax = plt.subplots(figsize=(12, 0.8 * len(chunk) + 1))
        ax.set_axis_off()
        table = Table(ax, bbox=[0, 0, 1, 1])

        col_labels = ["Name", "Created", "Description"]
        col_widths = [0.25, 0.15, 0.6]

        for j, label in enumerate(col_labels):
            table.add_cell(0, j, width=col_widths[j], height=0.5, text=label, loc='center', facecolor='lightgrey')

        for row_idx, threat in enumerate(chunk, 1):
            name = threat.get("name", "Unknown")
            created = threat.get("created", "N/A")
            description = threat.get("description", "No description")[:100] + '...'

            row_data = [name, created, description]
            for col_idx, text in enumerate(row_data):
                table.add_cell(row_idx, col_idx, width=col_widths[col_idx], height=0.5, text=text, loc='left')

        table.set_fontsize(10)
        ax.add_table(table)

        filename = f"debian_threat_table_{i//per_page + 1}.png"
        fig.savefig(filename, bbox_inches='tight')
        plt.close(fig)
        tables.append(filename)

    return tables

def main():
    if not OTX_KEY:
        raise EnvironmentError("OTX_KEY environment variable is not set")

    threats = fetch_threats()
    if not threats:
        print("No threats retrieved.")
        return

    files = generate_tables(threats)
    print(f"Generated {len(files)} threat detail table images.")

if __name__ == "__main__":
    main()
