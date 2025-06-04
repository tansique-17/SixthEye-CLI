import subprocess,time
import os
import tqdm
import pyfiglet
from tqdm import tqdm
from termcolor import colored

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
