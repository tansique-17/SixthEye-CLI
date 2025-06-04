import os, time
import subprocess
import requests, pyfiglet
from termcolor import colored
from urllib.parse import urlparse
import urllib3
from requests.exceptions import RequestException, ConnectTimeout
from concurrent.futures import ThreadPoolExecutor, as_completed

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


if __name__ == "__main__":
    clickjacking()
