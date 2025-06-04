
# 👁 Sixth Eye – CLI Recon Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow)
![Interface](https://img.shields.io/badge/interface-Terminal-brightgreen)
![Modules](https://img.shields.io/badge/modules-14-informational)

**Sixth Eye CLI** is a full-featured command-line reconnaissance framework developed in Python for security testing, intelligence gathering, and vulnerability analysis.

---

## 🔥 Core Features

| Module                | Functionality                                     |
|-----------------------|--------------------------------------------------|
| 🔍 DNS Records        | Fetch all DNS records                            |
| 🌐 ASN Info           | Get IP-to-ASN data                               |
| 🧠 WHOIS              | WHOIS info with pretty print & saving            |
| 🌐 Subdomains         | Subdomain enumeration using `subfinder`          |
| 🔐 Headers            | Security header analysis                         |
| 🧰 Tech Stack         | Technology and security product fingerprinting   |
| 🤖 Crawler            | Crawl the target using `katana`                  |
| 🗂️ Wayback URLs       | Pull historical archive links from Wayback       |
| 🧬 Wayback Files      | Filter for sensitive files in archive            |
| 🚪 Port Scanner       | Fast TCP port scan and service detection         |
| 🎯 Banner Grabbing    | Extract HTTP banners from pages                  |
| 📜 JS Crawler         | Find and crawl JavaScript URLs                   |
| ⚠️ Clickjacking       | Auto-check and PoC generation for vulns          |
| 🧪 All-in-One         | Run all modules in sequence                      |

---

## ⚙️ Requirements

- **Python ≥ 3.8**
- `subfinder`, `katana`, and other CLI tools must be available in PATH
- Run on **Linux or WSL** (mandatory for subprocess-based modules)

---

## 🧰 Setup Guide

### 🔧 1. Clone the repository

```bash
git clone https://github.com/tansique-17/SixthEye-CLI.git
cd SixthEye-CLI
python main.py
```

### ⚙️ 2. Run the install script (in Linux or WSL)

```bash
chmod +x install.sh
./install.sh
```

It installs:
- `subfinder`
- `katana`
- Required Python modules (from `requirements.txt`)

---

## 🚀 Running the Tool

```bash
sudo python3 main.py
```

> Root permissions required for some network operations (like port scanning).

---

## 📦 Example `install.sh`

```bash
#!/bin/bash

# Install dependencies
sudo apt update && sudo apt install -y subfinder katana python3-pip

# Install Python packages
pip3 install -r requirements.txt
```

---

## 🧑‍💻 Author

**Tansique Dasari**  
Cybersecurity Specialist, OSINT Analyst  
🔗 [LinkedIn](https://linkedin.com/in/tansique-dasari)  
🐛 [HackerOne](https://hackerone.com/tansique-17)  
🛡 [Bugcrowd](https://bugcrowd.com/tansique-17)

---

## 📜 License

MIT License – Free to use, modify, and distribute with proper attribution.

---

## ⚠️ Disclaimer

This tool is meant for **authorized security research and educational use only**.  
Do not run against systems you do not own or have explicit permission to test.

---
