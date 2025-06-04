#!/bin/bash

# Trap Ctrl+C to exit cleanly
trap ctrl_c INT
ctrl_c() {
  echo -e "\n[!] Ctrl+C detected. Cleaning up..."
  deactivate 2>/dev/null
  rm -rf sixth_eye_env install_log.txt
  echo "[ ✔   ] Exiting..."
  exit 1
}

clear
cat << "EOF"
  █████████  █████ █████ █████ ███████████ █████   █████    ██████████ █████ █████ ██████████
 ███░░░░░███░░███ ░░███ ░░███ ░█░░░███░░░█░░███   ░░███    ░░███░░░░░█░░███ ░░███ ░░███░░░░░█
░███    ░░░  ░███  ░░███ ███  ░   ░███  ░  ░███    ░███     ░███  █ ░  ░░███ ███   ░███  █ ░ 
░░█████████  ░███   ░░█████       ░███     ░███████████     ░██████     ░░█████    ░██████   
 ░░░░░░░░███ ░███    ███░███      ░███     ░███░░░░░███     ░███░░█      ░░███     ░███░░█   
 ███    ░███ ░███   ███ ░░███     ░███     ░███    ░███     ░███ ░   █    ░███     ░███ ░   █
░░█████████  █████ █████ █████    █████    █████   █████    ██████████    █████    ██████████
 ░░░░░░░░░  ░░░░░ ░░░░░ ░░░░░    ░░░░░    ░░░░░   ░░░░░    ░░░░░░░░░░    ░░░░░    ░░░░░░░░░░ 
EOF

echo "[ ✔   ] Starting installation..."

# ---- Handle dpkg lock ----
while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
      sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    sleep 10
done

# ---- System Update ----
sudo apt-get update -qq 2>/dev/null&& sudo apt-get upgrade -y -qq 2>/dev/null

# ---- Install Dependencies ----
echo "[ ✔   ] Connecting to Zephyr Servers !!"
sudo apt-get install -y python3-pip golang jq git python-is-python3 python-venv --only-upgrade -y -qq &>/dev/null
sudo apt install golang-go -y -qq &>/dev/null
sudo apt-get install -y libssl-dev libffi-dev python3-dev build-essential -y -qq &>/dev/null
sudo apt-get install -y libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev -y -qq &>/dev/null
sudo apt-get install -y libjpeg-dev libfreetype6-dev libpng-dev -y -qq &>/dev/null
sudo apt-get install -y libjpeg-dev libfreetype6-dev libpng-dev -y -qq &>/dev/null

# ---- Create Virtual Environment ----
echo "[ ✔   ] Initiating Encryption..."
rm -rf sixth_eye_env
python3 -m venv sixth_eye_env
source sixth_eye_env/bin/activate

# ---- Install Python Modules in Virtual Environment ----
echo "[ ✔   ] Connection Established..."
pip_modules=( 
    "builtwith" "colorama" "requests" "shodan" "mmh3" "PyExecJS" "python3-nmap"
    "beautifulsoup4" "fake-useragent" "googlesearch-python" "alive-progress"
    "python-whois" "aiohttp" "dnspython" "waybackpy" "ratelimit" "pyjwt" "boto3"
    "customtkinter" "Ctkmenubar" "pillow" "ipwhois" "bs4" "whois" "tkinter" "concurrent"
)
pip install --quiet "${pip_modules[@]}" &>/dev/null

# ---- Install Go-based Tools ----
echo "[ ✔   ] Downloading neccessary files..."
tools=(
    "nuclei github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "waybackurls github.com/tomnomnom/waybackurls@latest"
    "httprobe github.com/tomnomnom/httprobe@latest"
    "httpx github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "anew github.com/tomnomnom/anew@latest"
    "gau github.com/lc/gau/v2/cmd/gau@latest"
    "hakrawler github.com/hakluke/hakrawler@latest"
    "assetfinder github.com/tomnomnom/assetfinder@latest"
    "asnmap github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "katana github.com/projectdiscovery/katana/cmd/katana@latest"
)

for tool in "${tools[@]}"; do
    tool_name=${tool%% *}
    # Install the Go tool if it isn't already installed
    if ! command -v $tool_name &>/dev/null; then
        go install ${tool#* } &>/dev/null
        GOPATH=$(go env GOPATH)
        BIN_PATH="$GOPATH/bin/$tool_name"
        if [ -f "$BIN_PATH" ]; then
            sudo mv "$BIN_PATH" /usr/bin/ &>/dev/null
        fi
    fi

    # Check if the tool is working using `tool -h` (silent check)
    if ! $tool_name -h &>/dev/null; then
        go install ${tool#* } &>/dev/null
        GOPATH=$(go env GOPATH)
        BIN_PATH="$GOPATH/bin/$tool_name"
        if [ -f "$BIN_PATH" ]; then
            sudo mv "$BIN_PATH" /usr/bin/ &>/dev/null
        fi
    fi
    sleep 0.3
done

# ---- Install ParamSpider inside Virtual Environment ----
git clone https://github.com/devanshbatham/ParamSpider.git &>/dev/null
cd ParamSpider
pip install . &>/dev/null
deactivate
cd ..
rm -rf ParamSpider

# ---- Clean up ----
echo "[ ✔   ] Installing the Tools"
rm -rf sixth_eye_env install_log.txt
rm -rf ~/go/bin ~/go &>/dev/null
rm -rf /go/bin /go &>/dev/null

echo "[ ✔   ]====================================================================[ ✔   ]"
echo "[ ✔   ]                      Installation Complete!                        [ ✔   ]"
echo "[ ✔   ]====================================================================[ ✔   ]"
exit 0
