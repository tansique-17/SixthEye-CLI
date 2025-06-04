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
        
        
