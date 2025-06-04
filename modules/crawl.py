import subprocess,os,tqdm,pyfiglet,time
from tqdm import tqdm
from termcolor import colored

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

    
