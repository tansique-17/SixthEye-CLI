import requests,os,pyfiglet,tqdm,time
from tabulate import tabulate
from tqdm import tqdm
from termcolor import colored

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