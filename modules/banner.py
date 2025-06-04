import requests,pyfiglet,time
from termcolor import colored
from bs4 import BeautifulSoup
import os
from urllib.parse import urlparse, urljoin

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'

# Function to get headers and banner
def get_banner(url):
    try:
        response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10)
        banner = response.headers.get('Server', 'Unknown Server')
        return banner
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Function to find all links on a domain
def get_all_links(domain):
    links = set()
    visited = set()

    def crawl(url):
        if url in visited:
            return
        visited.add(url)
        try:
            response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                link_url = link['href']
                full_url = urljoin(url, link_url)  # Get absolute URL
                if full_url.startswith(domain):
                    links.add(full_url)
                    crawl(full_url)  # Recursively crawl linked pages
        except requests.exceptions.RequestException:
            pass

    crawl(domain)
    return links

# Function to save banners to text file
def save_banners_to_file(links, domain):
    if domain.endswith(".com"):
        dir = domain[:-4]
    if dir.startswith("http://"):
        domain1 = dir[7:]
    elif dir.startswith("https://"):
        domain1 = dir[8:]
    os.makedirs("results", exist_ok=True)  # Create directory if it doesn't exist
    os.makedirs(f"results/{dir}", exist_ok=True)

    with open(f"results/{dir}/{domain1}_banner.txt", "w") as f:
        for link in links:
            banner = get_banner(link)
            f.write(f"{link} - {banner}\n")
            print(f"{link} - {banner}")
    print(f"\nBanners saved to results/{dir}/{domain1}_banner.txt")
    return

# Main function
def banner(domain):
    

    if not domain.startswith('http'):
        domain = "http://" + domain  # Ensure 'http://' prefix if not present

    print(f"Grabbing banners from links on {domain}...\n")
    links = get_all_links(domain)
    save_banners_to_file(links, domain)
    print(f"\nBanners saved to results/{domain.split('//')[-1].split('/')[0]}/{domain}_banner.txt")
    return


