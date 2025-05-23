#!/bin/bash

echo "Installing Enhanced Surface Scanner dependencies..."

# Check OS type
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "[*] Installing Homebrew if not present..."
    which brew || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    echo "[*] Installing Go..."
    brew install go
    
    echo "[*] Installing GitHub CLI..."
    brew install gh
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "[*] Updating package lists..."
    sudo apt update
    
    echo "[*] Installing Go..."
    sudo apt install -y golang-go
    
    echo "[*] Installing GitHub CLI..."
    type -p curl >/dev/null || sudo apt install curl -y
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && sudo apt update \
    && sudo apt install gh -y
else
    echo "Unsupported operating system"
    exit 1
fi

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# Install Go tools
echo "[*] Installing Go-based tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Clone SecLists if not present
if [ ! -d "SecLists" ]; then
    echo "[*] Downloading SecLists..."
    git clone https://github.com/danielmiessler/SecLists.git
fi

echo "[*] Setting up GitHub authentication..."
gh auth status || gh auth login

echo "[+] Installation completed!"
echo "[*] You can now run: python3 surface_scanner.py --examples"