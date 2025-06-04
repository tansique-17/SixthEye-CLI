import subprocess,os,tqdm,pyfiglet,time
from tqdm import tqdm
from termcolor import colored

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
