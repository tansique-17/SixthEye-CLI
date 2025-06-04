import socket,time
import os,pyfiglet
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
import csv

def validate_input(input_data):
    try:
        socket.inet_aton(input_data)
        return 'ip', input_data
    except socket.error:
        try:
            ip = socket.gethostbyname(input_data)
            return 'url', ip
        except socket.gaierror:
            raise ValueError(f"Invalid input: {input_data}")

def scan_port(host, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "Unknown"
                return (port, "Open", service)
    except Exception:
        pass
    return None

def scan_ports(host, start_port=1, end_port=1024, max_workers=100):
    open_ports = []

    def handle_result(result):
        if result:
            open_ports.append(result)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, host, port)
            future.add_done_callback(lambda f: handle_result(f.result()))
            futures.append(future)

        for future in futures:
            future.result()

    return open_ports

def display_table(results):
    table = PrettyTable()
    table.field_names = ["Port", "Status", "Service"]
    for result in results:
        table.add_row(result)
    print(table)

def save_results(results, domain):
    # Format directory and filenames
    dir_name = domain.split(".")[0] if domain.endswith(".com") else domain.replace(".", "_")
    output_dir = f"results/{dir_name}"
    os.makedirs(output_dir, exist_ok=True)

    csv_path = f"{output_dir}/{domain}_ports.csv"
    txt_path = f"{output_dir}/{domain}_ports.txt"

    # Save as CSV
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Port", "Status", "Service"])
        for result in results:
            writer.writerow(result)

    # Save as TXT
    with open(txt_path, "w") as txtfile:
        for result in results:
            txtfile.write(f"Port {result[0]:5} | {result[1]:4} | {result[2]}\n")

    print(f"[✓] Results saved to:\n ├─ {csv_path}\n └─ {txt_path}")

def port_scanner(domain):
    
    print(colored("A simple port scanner to find open ports and services.","green"))

    start_port = input("Enter start port (default 1): ").strip()
    end_port = input("Enter end port (default 1024): ").strip()

    start_port = int(start_port) if start_port else 1
    end_port = int(end_port) if end_port else 1024

    try:
        _, validated_host = validate_input(domain)
        print(f"\n[+] Scanning domain: {domain} ({validated_host}) from port {start_port} to {end_port}...\n")
        results = scan_ports(validated_host, start_port, end_port)
        if results:
            display_table(results)
            save_results(results, domain)
        else:
            print(colored("[-] No open ports found."),"red")
        print("\n[✓] Scan complete.")
    except ValueError as e:
        print(colored(f"[!] {e}"),"red")

