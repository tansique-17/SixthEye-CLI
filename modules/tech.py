import requests
import os
import time
import pyfiglet
from tqdm import tqdm
import re
from tabulate import tabulate
from termcolor import colored
import csv
from collections import defaultdict
from urllib.parse import urlparse

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'

def load_tech_categories_and_patterns(file_name="tech_categories.txt"):
    tech_categories = {}
    waf_patterns = []
    edr_patterns = []
    soc_patterns = []

    current_category = None

    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, file_name)

    if not os.path.exists(file_path):
        print(colored(f"[!] tech_categories.txt not found at {file_path}", "red"))
        exit(1)

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current_category = line[1:-1].strip()
                if current_category not in tech_categories:
                    tech_categories[current_category] = []
                continue
            items = [item.strip() for item in line.split(",") if item.strip()]
            tech_categories[current_category].extend(items)

    waf_patterns = [item.lower() for item in tech_categories.get("WAF Patterns", [])]
    edr_patterns = [item.lower() for item in tech_categories.get("EDR Patterns", [])]
    soc_patterns = [item.lower() for item in tech_categories.get("SOC Patterns", [])]

    return tech_categories, waf_patterns, edr_patterns, soc_patterns

def detect_waf_edr_soc(headers, waf_patterns, edr_patterns, soc_patterns):
    detected = {'WAF': set(), 'EDR': set(), 'SOC': set()}
    for key, value in headers.items():
        header_value = value.lower()
        for pattern in waf_patterns:
            if pattern in header_value:
                detected['WAF'].add(pattern.capitalize())
        for pattern in edr_patterns:
            if pattern in header_value:
                detected['EDR'].add(pattern.capitalize())
        for pattern in soc_patterns:
            if pattern in header_value:
                detected['SOC'].add(pattern.capitalize())
    return detected

def detect_technologies(headers, content, tech_categories, waf_patterns, edr_patterns, soc_patterns):
    detected = {category: set() for category in tech_categories}
    detected['Detected WAF Types'] = set()
    detected['Detected EDR Vendors'] = set()
    detected['Detected SOC Platforms'] = set()

    for category, tech_list in tech_categories.items():
        if category in ['WAF Patterns', 'EDR Patterns', 'SOC Patterns']:
            continue
        for tech in tech_list:
            tech_lower = tech.lower()
            if any(tech_lower in h.lower() for h in headers.keys()) or \
               any(tech_lower in v.lower() for v in headers.values()) or \
               tech_lower in content:
                detected[category].add(tech)

    waf_edr_soc_detection = detect_waf_edr_soc(headers, waf_patterns, edr_patterns, soc_patterns)
    detected.setdefault('Security Technologies', set())
    if waf_edr_soc_detection['WAF']:
        detected['Security Technologies'].add("WAF")
        detected['Detected WAF Types'].update(waf_edr_soc_detection['WAF'])
    if waf_edr_soc_detection['EDR']:
        detected['Security Technologies'].add("EDR")
        detected['Detected EDR Vendors'].update(waf_edr_soc_detection['EDR'])
    if waf_edr_soc_detection['SOC']:
        detected['Security Technologies'].add("SOC")
        detected['Detected SOC Platforms'].update(waf_edr_soc_detection['SOC'])

    return {cat: list(techs) for cat, techs in detected.items() if techs}

def get_headers_and_content(domain):
    session = requests.Session()
    try:
        response = session.get(domain, headers={'User-Agent': USER_AGENT}, timeout=10, allow_redirects=True)
        redirect_chain = response.history
        parsed_domain = urlparse(response.url).netloc
        return response.headers, response.text.lower(), parsed_domain, redirect_chain
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Error fetching the domain: {e}", "red"))
        return {}, "", "", []

def display_single_table(detected_tech):
    def format_tech_list(techs, per_line=3):
        lines = []
        for i in range(0, len(techs), per_line):
            lines.append(", ".join(techs[i:i + per_line]))
        return "\n".join(lines)

    table_data = []
    for category, technologies in detected_tech.items():
        if technologies:
            formatted = format_tech_list(sorted(technologies), per_line=3)
            table_data.append([category, formatted])

    print(tabulate(table_data, headers=["Category", "Technologies"], tablefmt="grid"))

def save_results(detected_tech, domain):
    domain_name = urlparse(domain).netloc or domain
    if domain_name.endswith(".com"):
        dir = domain_name[:-4]
    if dir.startswith("http://"):
        dir = dir[7:]
    if dir.startswith("https://"):
        dir = dir[8:]
    os.makedirs("results", exist_ok=True)


    txt_path = f"results/{dir}{domain_name}_tech_scan_results.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"Scan Results for: {domain}\n")
        f.write("\nDetected Technologies & Security Stack:\n")
        for category, technologies in detected_tech.items():
            formatted = ", ".join(sorted(technologies))
            f.write(f"{category}: {formatted}\n")
    print(f"Results saved to {txt_path}")

    csv_path = f"results/{dir}/{domain_name}_tech_scan_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Category", "Technologies"])
        for category, technologies in detected_tech.items():
            formatted = ", ".join(sorted(technologies))
            writer.writerow([category, formatted])
    print(f"Results saved to {csv_path}")

def tech_detector(domain):
    tech_categories, waf_patterns, edr_patterns, soc_patterns = load_tech_categories_and_patterns()

    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "http://" + domain

    print(f"\nScanning {domain} ...")
    tqdm.write("This may take a few moments, please wait.")
    tqdm.write("Waiting for headers and content...")

    headers, content, final_domain, redirect_chain = get_headers_and_content(domain)

    if not headers:
        print(colored("[-] Could not fetch headers or content. Please check the URL and try again.", "red"))
        return

    if redirect_chain:
        print("\n[+] Redirect Chain:")
        for i, redirect in enumerate(redirect_chain):
            print(f"  [{i + 1}] {redirect.url} ->")

    detected_tech = detect_technologies(headers, content, tech_categories, waf_patterns, edr_patterns, soc_patterns)
    print("\nDetected Technologies & Security Stack:\n")
    display_single_table(detected_tech)

    print("\nScan complete!")
    save_results(detected_tech, domain)
    return 


