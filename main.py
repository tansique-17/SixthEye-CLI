import os
import sys,time
import pyfiglet
from modules.asn import asn_info, dns_info
from modules.headers import cli_security_headers
from modules.sub import subenum
from modules.who import cli_whois_lookup
from modules.tech import tech_detector
from termcolor import colored
from modules.crawl import crawl
from modules.wayfile import wayfile
from modules.wayback import wayback
from modules.ports import port_scanner
from modules.banner import banner
from modules.jscrawl import jscrawl
from modules.ClickVuln import clickjacking
from all import all


import os, time
import subprocess
import requests, pyfiglet
from termcolor import colored
from urllib.parse import urlparse
import urllib3
from requests.exceptions import RequestException, ConnectTimeout
from concurrent.futures import ThreadPoolExecutor, as_completed

import subprocess,os,tqdm,pyfiglet,time
from tqdm import tqdm
from termcolor import colored
import socket,time
import os,pyfiglet
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
import csv
import subprocess,time
import os
import tqdm
import pyfiglet
from tqdm import tqdm
from termcolor import colored
import requests,os,pyfiglet,tqdm,time
from tabulate import tabulate
from tqdm import tqdm
from termcolor import colored
import subprocess,os,tqdm,pyfiglet,time
from tqdm import tqdm
from termcolor import colored
import requests,pyfiglet,time
from termcolor import colored
from bs4 import BeautifulSoup
import os
from urllib.parse import urlparse, urljoin
import dns.resolver,os,pyfiglet,tqdm,time
from ipwhois import IPWhois
from termcolor import colored
from tabulate import tabulate
from tqdm import tqdm
from modules.asn import asn_info, dns_info
from modules.headers import cli_security_headers
from modules.sub import subenum
from modules.who import cli_whois_lookup
from modules.tech import tech_detector
from termcolor import colored
from modules.crawl import crawl
from modules.wayfile import wayfile
from modules.wayback import wayback
from modules.ports import port_scanner
from modules.banner import banner
from modules.jscrawl import jscrawl
from modules.ClickVuln import clickjacking
import pyfiglet,time
from termcolor import colored
import whois,os,pyfiglet,tqdm,time
from datetime import datetime
from tabulate import tabulate
from tqdm import tqdm
from termcolor import colored
import requests, time
import os,pyfiglet
from termcolor import colored
import os
import re
import time
import requests
import pyfiglet
from termcolor import colored
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
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




WAYBACK_URL = "https://web.archive.org/cdx/search/cdx"
FILE_EXTENSIONS = r'\.(bak|backup|bkp|old|save|tmp|temp|txt|log|conf|config|ini|yaml|yml|json|xml|csv|sql|db|sqlite3?|mdb|xls|xlsx|xlsm|xlsb|ods|docx?|pptx?|odt|rtf|pdf|md|tex|zip|rar|7z|gz|tar|tgz|tar\.gz|bz2|exe|dll|bin|apk|msi|img|iso|dmg|deb|rpm|sh|bat|ps1|crt|pem|key|pub|asc|env|passwd|shadow|htpasswd|htaccess|swp|swx|lock|log[0-9]*|bak[0-9]*|makefile|Dockerfile|gitignore|gitattributes|csr|der|py|js|java|php|asp|aspx|jsp|rb|go|pl|c|cpp|cs|ts)'
CHUNK_SIZE = 100
THREADS = 20


def fetch_wayback_links(domain):
    """Fetch URLs from Wayback Machine and save to hidden file."""
    params = {
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey"
    }
    try:
        print(f"[+] Fetching Wayback URLs for {domain}...")
        response = requests.get(WAYBACK_URL, params=params, timeout=20)
        if response.status_code == 200:
            urls = response.text.splitlines()
            os.makedirs("results", exist_ok=True)
            hidden_file = f".wayback_{domain}.txt"
            with open(hidden_file, "w") as f:
                f.write("\n".join(urls))
            print(f"[+] {len(urls)} URLs saved to {hidden_file}")
            return hidden_file
    except Exception as e:
        print(f"[-] Error fetching URLs: {e}")
    return None


def load_links_from_file(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]


def filter_filetype_urls(urls):
    return [url for url in urls if re.search(FILE_EXTENSIONS, url, re.IGNORECASE)]


def check_url(url):
    try:
        res = requests.head(url, timeout=5)
        if res.status_code == 200:
            return url
    except:
        return None


def validate_urls_chunked(urls, domain):
    valid = []
    for i in range(0, len(urls), CHUNK_SIZE):
        chunk = urls[i:i+CHUNK_SIZE]
        print(f"[+] Checking chunk {i+1} to {i+len(chunk)}")
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            results = list(tqdm(executor.map(check_url, chunk), total=len(chunk)))
            valid.extend([url for url in results if url])
        time.sleep(1)  # polite delay to avoid rate-limiting
    return valid


def wayfile(domain):
    

    if not domain:
        print("[-] No domain entered.")
        return
    
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if domain.endswith("/"):
        domain = domain[:-1]
    if domain.endswith(".com"):
        dir = domain[:-4]

    hidden_file = fetch_wayback_links(domain)
    if not hidden_file:
        print("[-] Could not fetch links.")
        return

    urls = load_links_from_file(hidden_file)
    filtered_urls = filter_filetype_urls(urls)
    print(f"[+] {len(filtered_urls)} URLs with interesting file extensions found.")

    valid_urls = validate_urls_chunked(filtered_urls, domain)
    print(f"[+] {len(valid_urls)} valid URLs with 200 OK.")
    print(f"[+] Saving valid URLs to {domain}_valid.txt")
    os.makedirs("results", exist_ok=True)
    os.makedirs(f"results/{dir}", exist_ok=True)
    valid_file = f"results/{dir}/{domain}_valid.txt"
    with open(valid_file, "w") as f:
        f.write("\n".join(valid_urls))

    print(f"[+] Results saved to {valid_file}")
    print(f"[+] Done.")
    os.remove(hidden_file)  # Clean up hidden file
    return





WAYBACK_URL = "https://web.archive.org/cdx/search/cdx"

def fetch_wayback_urls(domain):
    """Fetch and save Wayback Machine URLs for a domain."""
    print(f"[+] Fetching Wayback URLs for {domain}...")
    params = {
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey"
    }
    if domain.endswith(".com"):
        dir = domain[:-4]
    try:
        response = requests.get(WAYBACK_URL, params=params, timeout=30)
        if response.status_code == 200:
            urls = response.text.splitlines()
            if not urls:
                print("[-] No URLs found.")
                return None
            
            os.makedirs("results", exist_ok=True)
            os.makedirs(f"results/{dir}", exist_ok=True)

            output_file = f"results/{dir}/wayback_{domain}.txt"
            if os.path.exists(output_file):
                print(f"[!] File {output_file} already exists. Overwriting...")
            else:
                print(f"[+] Saving to {output_file}")
            with open(output_file, "w") as f:
                f.write("\n".join(urls))
            print(f"[✓] Saved {len(urls)} URLs to {output_file}")

            return output_file
        else:
            print(colored(f"[-] Failed to fetch data. Status Code: {response.status_code}"),"red")
    except Exception as e:
        print(f"[-] Error: {e}")
    return None


def wayback(domain):
    
    if not domain:
        print(colored("[-] No domain entered."),"red")
        return
    fetch_wayback_urls(domain)

    print(colored("[✓] Wayback URLs fetched successfully!","green"))
    return





def format_field(field):
    if isinstance(field, list):
        return "\n".join(str(f.strftime("%Y-%m-%d %H:%M:%S") if isinstance(f, datetime) else f) for f in field)
    elif isinstance(field, datetime):
        return field.strftime("%Y-%m-%d %H:%M:%S")
    return str(field)

def get_whois_info(domain, print_output=True):
    """
    Retrieves WHOIS info for a domain.

    Args:
        domain (str): The domain name to look up.
        print_output (bool): Whether to print formatted table output.

    Returns:
        dict: Dictionary containing WHOIS fields or error message.
    """
    try:
        domain_info = whois.whois(domain)

        fields = {
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Updated Date": domain_info.updated_date,
            "Name Servers": domain_info.name_servers,
            "Emails": domain_info.emails,
            "Organization": domain_info.org,
            "Country": domain_info.country
        }

        if print_output:
            print("\n" + "=" * 42)
            print(" WHOIS INFORMATION ".center(42, "="))
            formatted = [[key, format_field(value)] for key, value in fields.items()]
            print(tabulate(formatted, headers=["Field", "Value"], tablefmt="grid"))
            print("=" * 42 + "\n")

        return fields

    except Exception as e:
        if print_output:
            print(f"[!] Error fetching WHOIS info: {e}")
        return {"error": str(e)}

def cli_whois_lookup(domain):
    tqdm.write("This may take a few moments, please wait.")
    tqdm.write("Waiting for WHOIS information...")
    get_whois_info(domain)
    if domain.endswith(".com"):
        dir = domain[:-4]
    print("\n[🔍] WHOIS Lookup Complete!")
    os.makedirs("results", exist_ok=True)
    with open(f"results/{dir}/{domain}_whois.txt", "w") as f:
        f.write("WHOIS Lookup Results for: " + domain + "\n")
        f.write("=" * 42 + "\n")
        f.write(" WHOIS INFORMATION \n")
        f.write("=" * 42 + "\n")
        for key, value in get_whois_info(domain, print_output=False).items():
            f.write(f"{key}: {format_field(value)}\n")
        f.write("=" * 42 + "\n")
        

    print(f"Results saved to results/{dir}/{domain}_whois.txt")

    return


def all(domain):
    
    print(f"Running all modules on {domain}...")
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("🔍 DNS Lookup","doom"),"cyan"))
    print("-------------------------------")
    dns_info(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("🌐 ASN Lookup"),"cyan"))
    print("-------------------------------")
    asn_info(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("🔍 Whois Lookup"),"cyan"))
    print("-------------------------------")
    cli_whois_lookup(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("Sub Enum","doom"),"cyan"))
    print("-------------------------------")
    subenum(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("Header Analysis", "doom"),"cyan"))
    print("-------------------------------")
    cli_security_headers(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("Tech Detector", "doom"),"cyan"))
    print("-------------------------------")
    tech_detector(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("Crawler", "doom"),"cyan"))
    print("-------------------------------")
    crawl(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("WayBackFetch", "doom"),"cyan"))
    print("-------------------------------")
    wayback(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("WayFile", "doom"),"cyan"))
    print("-------------------------------")
    wayfile(domain)

    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("Port Scanner", "doom"),"cyan"))
    print("-------------------------------")
    port_scanner(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("Banner Grabbing", "doom"),"cyan"))
    print("-------------------------------")
    banner(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("JSCrawl", "doom"),"cyan"))
    print("-------------------------------")
    jscrawl(domain)
    time.sleep(1)
    print("-------------------------------")
    print(colored(pyfiglet.figlet_format("ClickJacking", "doom"),"cyan"))
    print("-------------------------------")
    clickjacking(domain)
    time.sleep(1)
    return
        
        

record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']

def get_dns_records(domain):
    results = []
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                results.append([rtype, rdata.to_text()])
        except Exception:
            continue
    return results

def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res.get("asn"), res.get("asn_description")
    except Exception:
        return None, None

def extract_ips_and_asns(domain):
    ip_records = []
    for rtype in ['A', 'AAAA']:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                ip = rdata.to_text()
                asn, desc = get_asn_info(ip)
                ip_records.append([rtype, ip, asn or "Not Found", desc or "Not Found"])
        except Exception:
            continue
    return ip_records

def extract_mx_records(domain):
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        for rdata in answers:
            mx_records.append(['MX', rdata.exchange.to_text()])
    except Exception:
        pass
    return mx_records

def dns_info(domain):
    
    if domain.endswith(".com"):
        dir = domain[:-4]
    time.sleep(1)
    print(f"\n🔍 DNS Records for {domain}:")
    time.sleep(1)
    tqdm.write("This may take a few moments, please wait.")
    time.sleep(1)
    tqdm.write("Waiting for DNS records...")
    dns_records = get_dns_records(domain)
    print(tabulate(dns_records, headers=["Record Type", "Value"], tablefmt="grid"))
    print("\n")
    os.makedirs("results", exist_ok=True)
    os.makedirs(f"results/{dir}", exist_ok=True)
    time.sleep(0.5)
    print("Sabing results ...")
    with open(f"results/{dir}/{domain}_dns_records.txt", "w") as file:
        for record in dns_records:
            file.write(f"{record[0]}: {record[1]}\n")
    print(f"DNS records saved to results/{dir}/{domain}_dns_records.txt")
    
    return None

def asn_info(domain):
    
    if domain.endswith(".com"):
        dir = domain[:-4]

    print(f"\n🌐 ASN Info for IP Records of {domain}:")
    tqdm.write("This may take a few moments, please wait.")
    tqdm.write("Waiting for ASN info...")

    ip_asn_table = extract_ips_and_asns(domain)
    print(tabulate(ip_asn_table, headers=["Record Type", "IP Address", "ASN", "ASN Description"], tablefmt="fancy_grid"))
    print("\n")
    os.makedirs("results", exist_ok=True)
    os.makedirs(f"results/{dir}", exist_ok=True)
    with open(f"results/{dir}/{domain}_ip_asn_info.txt", "w") as file:
        for record in ip_asn_table:
            file.write(f"{record[0]}: {record[1]}, ASN: {record[2]}, Description: {record[3]}\n")
    print(f"IP ASN info saved to results/{dir}/{domain}_ip_asn_info.txt")
    return None




USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'

# Function to get headers and banner
def get_banner(url):
    try:
        response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10)
        banner = response.headers.get('Server', 'Unknown Server')
        return banner
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Function to find all links on a domain
def get_all_links(domain):
    links = set()
    visited = set()

    def crawl(url):
        if url in visited:
            return
        visited.add(url)
        try:
            response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                link_url = link['href']
                full_url = urljoin(url, link_url)  # Get absolute URL
                if full_url.startswith(domain):
                    links.add(full_url)
                    crawl(full_url)  # Recursively crawl linked pages
        except requests.exceptions.RequestException:
            pass

    crawl(domain)
    return links

# Function to save banners to text file
def save_banners_to_file(links, domain):
    if domain.endswith(".com"):
        dir = domain[:-4]
    if dir.startswith("http://"):
        domain1 = dir[7:]
    elif dir.startswith("https://"):
        domain1 = dir[8:]
    os.makedirs("results", exist_ok=True)  # Create directory if it doesn't exist
    os.makedirs(f"results/{dir}", exist_ok=True)

    with open(f"results/{dir}/{domain1}_banner.txt", "w") as f:
        for link in links:
            banner = get_banner(link)
            f.write(f"{link} - {banner}\n")
            print(f"{link} - {banner}")
    print(f"\nBanners saved to results/{dir}/{domain1}_banner.txt")
    return

# Main function
def banner(domain):
    

    if not domain.startswith('http'):
        domain = "http://" + domain  # Ensure 'http://' prefix if not present

    print(f"Grabbing banners from links on {domain}...\n")
    links = get_all_links(domain)
    save_banners_to_file(links, domain)
    print(f"\nBanners saved to results/{domain.split('//')[-1].split('/')[0]}/{domain}_banner.txt")
    return




def crawl(domain):

    

    try:
        process = subprocess.Popen(f"katana -u {domain} -d 5 -silent", shell=True, stdout=subprocess.PIPE, text=True)
        tqdm.write(f"🔍 Crawling in progress for {domain}...")
        tqdm.write("This may take a few moments, please wait.")
        tqdm.write("Results will be saved in the 'results' directory.")
        if domain.endswith(".com"):
            dir = domain[:-4]
        for sub in iter(process.stdout.readline, ''):
            print(sub.strip())
            os.makedirs("results", exist_ok=True)
            os.makedirs(f"results/{dir}", exist_ok=True)
            with open(f"results/{dir}/{domain}_crawl.txt", "a") as file:
                file.write(sub.strip() + "\n")
        tqdm.write(f"crawl completed for {domain}.")
        tqdm.write(f"Results saved to results/{dir}/{domain}_crawl.txt")
        process.stdout.close()
        process.wait()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        return
    return

    


# ✅ Commonly Recommended Security Headers
security_headers = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Expect-CT",
    "X-XSS-Protection", "Access-Control-Allow-Origin", "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"
]

def analyze_security_headers(domain, print_output=True):
    """
    Analyzes the presence of recommended security headers on a given domain.
    
    Args:
        domain (str): The domain to scan.
        print_output (bool): If True, prints the result in a table format.
    
    Returns:
        dict: A dictionary with 'present' and 'not_present' lists.
    """
    try:
        if not domain.startswith("http"):
            domain = "https://" + domain

        response = requests.get(domain, timeout=10)
        headers = response.headers

        present = []
        not_present = []

        for header in security_headers:
            if header in headers:
                present.append(header)
            else:
                not_present.append(header)

        if print_output:
            max_len = max(len(present), len(not_present))
            present += [""] * (max_len - len(present))
            not_present += [""] * (max_len - len(not_present))
            table = list(zip(present, not_present))
            print("\n[🔐] Security Headers Analysis for:", domain)
            print(tabulate(table, headers=["✅ Present", "❌ Not Present"], tablefmt="fancy_grid"))

        return {"present": present, "not_present": not_present}

    except Exception as e:
        if print_output:
            print(f"[!] Error fetching headers from {domain}: {e}")
        return {"error": str(e)}

# Optional CLI usage when running this file directly
def cli_security_headers(domain):
    analyze_security_headers(domain)
    if domain.endswith(".com"):
        dir = domain[:-4]
    tqdm.write(f"\n🔐 Security Headers Analysis for {domain}...")
    tqdm.write("This may take a few moments, please wait.")
    tqdm.write("Waiting for security headers...")
    print("\n[🔐] Security Headers Analysis Complete!")
    os.makedirs("results", exist_ok=True)
    os.makedirs(f"results/{dir}", exist_ok=True)
    with open(f"results/{dir}/{domain}_security_headers_analysis.txt", "w") as f:
        f.write("Security Headers Analysis for: " + domain + "\n")
        f.write("Present Headers:\n")
        for header in security_headers:
            f.write(f"  - {header}\n")    
        f.write("\nNot Present Headers:\n")
        for header in security_headers:
            f.write(f"  - {header}\n")
        f.write("\n[🔐] Security Headers Analysis Complete!\n")
    print(f"Results saved to results/{dir}/{domain}_security_headers_analysis.txt")    

    return

def jscrawl(domain):
    

    try:
        # Run katana with JavaScript file extension filter
        process = subprocess.Popen(f"katana -u {domain} -d 5 -em js -silent", shell=True, stdout=subprocess.PIPE, text=True)
        tqdm.write(f"🔍 Crawling in progress for {domain} (JavaScript files)...")
        tqdm.write("This may take a few moments, please wait.")
        tqdm.write("Results will be saved in the 'results' directory.")
        
        if domain.endswith(".com"):
            dir = domain[:-4]
        
        os.makedirs("results", exist_ok=True)
        os.makedirs(f"results/{dir}", exist_ok=True)

        # Process the output of the katana crawl
        for sub in iter(process.stdout.readline, ''):
            print(sub.strip())
            with open(f"results/{dir}/{domain}_js_crawl.txt", "a") as file:
                file.write(sub.strip() + "\n")
        
        tqdm.write(f"Crawl completed for {domain}.")
        tqdm.write(f"Results saved to results/{dir}/{domain}_js_crawl.txt")
        
        process.stdout.close()
        process.wait()
    
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        return

    return

def validate_input(input_data):
    try:
        socket.inet_aton(input_data)
        return 'ip', input_data
    except socket.error:
        try:
            ip = socket.gethostbyname(input_data)
            return 'url', ip
        except socket.gaierror:
            raise ValueError(f"Invalid input: {input_data}")

def scan_port(host, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "Unknown"
                return (port, "Open", service)
    except Exception:
        pass
    return None

def scan_ports(host, start_port=1, end_port=1024, max_workers=100):
    open_ports = []

    def handle_result(result):
        if result:
            open_ports.append(result)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, host, port)
            future.add_done_callback(lambda f: handle_result(f.result()))
            futures.append(future)

        for future in futures:
            future.result()

    return open_ports

def display_table(results):
    table = PrettyTable()
    table.field_names = ["Port", "Status", "Service"]
    for result in results:
        table.add_row(result)
    print(table)

def save_results(results, domain):
    # Format directory and filenames
    dir_name = domain.split(".")[0] if domain.endswith(".com") else domain.replace(".", "_")
    output_dir = f"results/{dir_name}"
    os.makedirs(output_dir, exist_ok=True)

    csv_path = f"{output_dir}/{domain}_ports.csv"
    txt_path = f"{output_dir}/{domain}_ports.txt"

    # Save as CSV
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Port", "Status", "Service"])
        for result in results:
            writer.writerow(result)

    # Save as TXT
    with open(txt_path, "w") as txtfile:
        for result in results:
            txtfile.write(f"Port {result[0]:5} | {result[1]:4} | {result[2]}\n")

    print(f"[✓] Results saved to:\n ├─ {csv_path}\n └─ {txt_path}")

def port_scanner(domain):
    
    print(colored("A simple port scanner to find open ports and services.","green"))

    start_port = input("Enter start port (default 1): ").strip()
    end_port = input("Enter end port (default 1024): ").strip()

    start_port = int(start_port) if start_port else 1
    end_port = int(end_port) if end_port else 1024

    try:
        _, validated_host = validate_input(domain)
        print(f"\n[+] Scanning domain: {domain} ({validated_host}) from port {start_port} to {end_port}...\n")
        results = scan_ports(validated_host, start_port, end_port)
        if results:
            display_table(results)
            save_results(results, domain)
        else:
            print(colored("[-] No open ports found."),"red")
        print("\n[✓] Scan complete.")
    except ValueError as e:
        print(colored(f"[!] {e}"),"red")
    return



def subdomain_enum(domain):
    try:
        process = subprocess.Popen(f"subfinder -d {domain} -all -silent", shell=True, stdout=subprocess.PIPE, text=True)
        tqdm.write(f"🔍 Subdomain enumeration in progress for {domain}...")
        tqdm.write("This may take a few moments, please wait.")
        tqdm.write("Press Ctrl+C to cancel the process.")
        tqdm.write("Results will be saved in the 'results' directory.")
        if domain.endswith(".com"):
            dir = domain[:-4]
        for sub in iter(process.stdout.readline, ''):
            print(sub.strip())
            os.makedirs("results", exist_ok=True)
            os.makedirs(f"results/{dir}", exist_ok=True)
            with open(f"results/{dir}/{domain}_subdomains.txt", "a") as file:
                file.write(sub.strip() + "\n")
        tqdm.write(f"Subdomain enumeration completed for {domain}.")
        tqdm.write(f"Results saved to results/{dir}/{domain}_subdomains.txt")
        process.stdout.close()
        process.wait()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
        return

def subenum(domain):
    subdomain_enum(domain)
    return

# Disable SSL certificate warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Retry settings
MAX_RETRIES = 3
TIMEOUT = 10  # seconds

def subdomain_enum(domain):
    """Enumerates subdomains using subfinder"""
    try:
        process = subprocess.Popen(f"subfinder -d {domain} -silent", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        subdomains = []
        hidden_file_path = f".{domain}_subdomains.txt"
        os.makedirs(f"results/{domain}", exist_ok=True)

        # Read subdomains from the process output and save them to the hidden file
        for sub in iter(process.stdout.readline, ''):
            sub = sub.strip()
            if sub:
                subdomains.append(sub)

        error_output = process.stderr.read()
        if error_output:
            pass  # Suppress error output

        with open(hidden_file_path, "w") as file:
            file.write("\n".join(subdomains))

        process.stdout.close()
        process.stderr.close()
        process.wait()

        return hidden_file_path  # Return the path to the hidden file
    except subprocess.CalledProcessError as e:
        print(colored(f"Error during subdomain enumeration: {e}", "red"))
        return None

def check_clickjacking_for_subdomain(subdomain, domain):
    """Check a single subdomain for clickjacking vulnerability"""
    sub_url = f"https://{subdomain}"
    
    try:
        response = requests.get(sub_url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        
        # Only proceed if the status code is 200 OK
        if response.status_code != 200:
            return
        
        headers = response.headers
        print(colored(f"Checking {subdomain}: {response.status_code}", "light_magenta"))
        time.sleep(1)
        # Check for X-Frame-Options and Content-Security-Policy headers
        
        xfo = headers.get("X-Frame-Options")
        csp = headers.get("Content-Security-Policy")

        if not xfo and not csp:
            print(colored(f"{subdomain} is vulnerable to Clickjacking","light_green"))
            time.sleep(1)
            save_clickjacking_poc(sub_url, domain, subdomain)
        else:
            print(colored(f"{subdomain} is protected with X-Frame-Options or CSP", "light_red"))

    except (RequestException, ConnectTimeout, requests.exceptions.Timeout, requests.exceptions.SSLError) as e:
        # Suppress errors that are related to connection or request issues (e.g., timeout, connection error, etc.)
        pass

    except urllib3.exceptions.NameResolutionError:
        # Silently skip subdomains with NameResolutionError
        pass

def save_clickjacking_poc(url, domain, subdomain):
    """Save PoC for clickjacking vulnerability"""
    print(colored("Generating PoC...", "magenta"))
    time.sleep(1)
    print(colored("Saving PoC...", "magenta"))
    os.makedirs(f"results/{domain}/ClickPOC", exist_ok=True)
    poc_path = f"results/{domain}/ClickPOC/{subdomain}_poc.html"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
</head>
<body>
    <h2>Clickjacking Proof-of-Concept for {url}</h2>
    <iframe src="{url}" width="800" height="600" style="opacity:0.8;"></iframe>
</body>
</html>
"""
    with open(poc_path, "w") as f:
        f.write(html.strip())
    print(colored(f"💡 PoC saved to: {poc_path}", "blue"))

def clean_up_hidden_file(file_path):
    """Deletes the hidden subdomains file after usage"""
    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass  # Ignore if the file doesn't exist

def check_clickjacking(domain, subdomains_file):
    """Check for Clickjacking vulnerabilities using parallel threads"""
    with open(subdomains_file, "r") as file:
        subdomains = [line.strip() for line in file.readlines()]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_clickjacking_for_subdomain, sub, domain) for sub in subdomains]
        
        for future in as_completed(futures):
            future.result()  # Wait for each task to complete

def clickjacking(domain):
    """Main Clickjacking vulnerability detection function"""
    

    # 1. Perform subdomain enumeration
    time.sleep(1)
    print(colored("Performing subdomain enumeration...", "yellow"))
    time.sleep(1)
    print(colored("This may take a few moments, please wait.", "magenta"))
    hidden_subdomains_file = subdomain_enum(domain)

    if hidden_subdomains_file:
        # 2. Check for Clickjacking vulnerability on each subdomain
        print(colored("Checking for Clickjacking vulnerabilities...", "yellow"))
        print(colored("This may take a few moments, please wait.", "magenta"))
        check_clickjacking(domain, hidden_subdomains_file)

        # 3. Clean up hidden subdomains file after usage
        clean_up_hidden_file(hidden_subdomains_file)
    return




def check_root():
    if os.name != 'nt':  # Check for non-Windows systems
        if os.geteuid() != 0:
            print(colored("This script must be run as root. Exiting...", 'red'))
            sys.exit(1)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clears the console

def choice(option):
    clear_console()  # Clears the console before displaying the main menu
    if option == 1:
        print(colored(pyfiglet.figlet_format("🔍 DNS Lookup Tool","doom"),"cyan"))
        domain = input("Enter a domain: ").strip()
        dns_info(domain)
        go_back_to_main()
        return
    elif option == 2:
        print(colored(pyfiglet.figlet_format("🌐 ASN Lookup Tool"),"cyan"))
        domain = input("Enter a domain: ").strip()
        asn_info(domain)
        go_back_to_main()
        return
    elif option == 3:
        print(colored(pyfiglet.figlet_format("WHOIS", "doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        cli_whois_lookup(domain)
        go_back_to_main()
        return
    elif option == 4:
        print(colored(pyfiglet.figlet_format("Sub Enum","doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        subenum(domain)
        go_back_to_main()
        return
    elif option == 5:
        print(colored(pyfiglet.figlet_format("Header Analysis", "doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        cli_security_headers(domain)
        go_back_to_main()
        return
    elif option == 6:
        print(colored(pyfiglet.figlet_format("Tech Detector", "doom"), "cyan"))
        domain = input("Enter a domain: ").strip()
        tech_detector(domain)
        go_back_to_main()
        return
    elif option == 7:
        print(colored(pyfiglet.figlet_format("Crawler", "doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        crawl(domain)
        go_back_to_main()
        return
    elif option == 8:
        print(colored(pyfiglet.figlet_format("WayBackFetch", "doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        wayback(domain)
        go_back_to_main()
        return
    elif option == 9:
        print(colored(pyfiglet.figlet_format("WayFile", "doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        wayfile(domain)
        go_back_to_main()
        return
    elif option == 10:
        print(colored(pyfiglet.figlet_format("Port Scanner", "doom")),"cyan")
        domain = input("Enter a domain: ").strip()
        port_scanner(domain)
        go_back_to_main()
        return
    elif option == 11:
        print(colored(pyfiglet.figlet_format("Banner Grabbing", "doom"),'cyan'))
        domain = input("Enter a domain: ").strip()
        banner(domain)
        go_back_to_main()
        return
    elif option == 12:
        print(colored(pyfiglet.figlet_format("JS Crawler", "doom")), "cyan")
        domain = input("Enter a domain: ").strip()
        jscrawl(domain)
        go_back_to_main()
        return
    elif option == 13:
        print(colored(pyfiglet.figlet_format("Clickjacking  Identification"), "cyan"))
        domain = input("Enter a domain: ").strip()
        clickjacking(domain)
        go_back_to_main()
        return
    elif option == 14:
        print(colored(pyfiglet.figlet_format("All Modules"), 'green'))
        domain = input("Enter a domain: ").strip()
        all(domain)
        go_back_to_main()
        return
    elif option == 99:
        print(colored("Thank you for using the Sixth Eye Recon Tool!", 'blue'))
        print(colored("Goodbye!", 'blue'))
        print(colored("Exiting...", 'red'))
        # Optional: Add a delay before exiting
        time.sleep(2)
        clear_console()
        sys.exit(0)
    else:
        print(colored("Invalid option. Please choose a valid option (1-7).", 'yellow'))
        return

def go_back_to_main():
    input(colored("\nPress any key to go back to the main menu...", 'green'))
    clear_console()  # Clears the console before displaying the main menu again

def main():
    check_root()  # Ensure the script is run as root
    clear_console()  # Clear the console when the tool starts
    while True:
        banner = """
  █████████  █████ █████ █████ ███████████ █████   █████    ██████████ █████ █████ ██████████
 ███░░░░░███░░███ ░░███ ░░███ ░█░░░███░░░█░░███   ░░███    ░░███░░░░░█░░███ ░░███ ░░███░░░░░█
░███    ░░░  ░███  ░░███ ███  ░   ░███  ░  ░███    ░███     ░███  █ ░  ░░███ ███   ░███  █ ░ 
░░█████████  ░███   ░░█████       ░███     ░███████████     ░██████     ░░█████    ░██████   
 ░░░░░░░░███ ░███    ███░███      ░███     ░███░░░░░███     ░███░░█      ░░███     ░███░░█   
 ███    ░███ ░███   ███ ░░███     ░███     ░███    ░███     ░███ ░   █    ░███     ░███ ░   █
░░█████████  █████ █████ █████    █████    █████   █████    ██████████    █████    ██████████
 ░░░░░░░░░  ░░░░░ ░░░░░ ░░░░░    ░░░░░    ░░░░░   ░░░░░    ░░░░░░░░░░    ░░░░░    ░░░░░░░░░░ 
"""
        print(colored(banner, 'cyan'))
        print(colored("Recon Tool v1.0 by Tansique Dasari", 'red'))
        print(colored("Welcome to the Sixth Eye Recon Tool!", 'blue'))
        print(colored("Choose an option:", 'yellow'))
        print(colored("1. DNS Records", 'green'))
        print(colored("2. ASN Info", 'green'))
        print(colored("3. WHOIS Lookup", 'green'))
        print(colored("4. Subdomain Enumeration", 'green'))
        print(colored("5. Security Headers Analysis", 'green'))
        print(colored("6. Technology Detection", 'green'))
        print(colored("7. Crawl", 'green'))
        print(colored("8. WayBack Fetcher", 'green'))
        print(colored("9. WayBack File Fetcher","green"))
        print(colored("10. Port Scanner", 'green'))
        print(colored("11. Banner Grabber", 'green'))
        print(colored("12. JS Crawl", 'green'))
        print(colored("13. Clickjacking Vulnerability", 'green'))
        print(colored("14. All Modules", 'green'))
        print(colored("99. Exit", 'red'))
        option = int(input(colored("Enter your choice: ", 'yellow')))
        choice(option)

if __name__ == "__main__":
    main()
