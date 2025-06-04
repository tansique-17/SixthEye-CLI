import os
import re
import time
import requests
import pyfiglet
from termcolor import colored
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

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



