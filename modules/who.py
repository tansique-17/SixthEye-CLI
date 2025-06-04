import whois,os,pyfiglet,tqdm,time
from datetime import datetime
from tabulate import tabulate
from tqdm import tqdm
from termcolor import colored

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