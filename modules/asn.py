import dns.resolver,os,pyfiglet,tqdm,time
from ipwhois import IPWhois
from termcolor import colored
from tabulate import tabulate
from tqdm import tqdm

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

