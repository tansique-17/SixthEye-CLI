import requests, time
import os,pyfiglet
from termcolor import colored

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



