#!/bin/bash

# --- Couleurs pour le terminal ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Starting Nmap-Pro-Analyzer installation...${NC}"

# 1. Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Please install it first.${NC}"
    exit 1
fi

# 2. Install Python dependencies
echo -e "${BLUE}[*] Installing dependencies (python-nmap, rich)...${NC}"
pip3 install python-nmap rich --break-system-packages

# 3. Make the main script executable
echo -e "${BLUE}[*] Setting permissions...${NC}"
chmod +x nmap_pro_analyzer.py

# 4. Create a symbolic link in /usr/local/bin
echo -e "${BLUE}[*] Creating symbolic link to /usr/local/bin/nmap-pro...${NC}"
sudo ln -sf "$(pwd)/nmap_pro_analyzer.py" /usr/local/bin/nmap-pro

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Installation successful!${NC}"
    echo -e "${GREEN}[+] You can now run the tool using: nmap-pro --help${NC}"
else
    echo -e "${RED}[!] Installation failed. Check your permissions.${NC}"
fi
