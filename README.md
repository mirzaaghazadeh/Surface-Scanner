# 🎯 Surface Scanner - Bug Bounty Automation Tool

An all-in-one scanning tool for bug bounty hunters.

## 🚀 Features

- **Subdomain Discovery**
  - crt.sh scanning
  - Subfinder integration
  - Common name variations
  - DNS resolution

- **URL Discovery & Processing**
  - Waybackurls / GAU integration
  - URL optimization with uro
  - Live URL checking with httpx
  - Parameter discovery with arjun

- **Content Discovery**
  - Directory bruteforcing (ffuf)
  - Sensitive file checking
  - Multiple wordlist support
  - Custom patterns

- **Information Gathering**
  - GitHub dorking
  - Google dork generation
  - Parameter discovery
  - Sensitive file detection

## 🛠️ Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/mirzaaghazadeh/surface-scanner
cd surface-scanner
```

2. **Run installation script**
```bash
chmod +x install.sh
./install.sh
```

3. **Authenticate with GitHub**
```bash
gh auth login
```

4. **Create domain list**
```bash
echo "example.com" > domains.txt
```

5. **Run scan**
```bash
python3 surface_scanner.py -d main-domains.txt
```

## 📋 Usage Examples

### Full Scan
```bash
python3 surface_scanner.py -d main-domains.txt
```

### Specific Modules
```bash
# Only GitHub dorking
python3 surface_scanner.py -d main-domains.txt --github-dork

# Only subdomain discovery
python3 surface_scanner.py -d main-domains.txt --subdomain

# Only URL discovery
python3 surface_scanner.py -d main-domains.txt --urls

# Only parameter discovery
python3 surface_scanner.py -d main-domains.txt --params

# Only directory bruteforcing
python3 surface_scanner.py -d main-domains.txt --dirs
```

### Advanced Options
```bash
# Continue from specific step
python3 surface_scanner.py -d main-domains.txt --from-step 3

# Custom output directory
python3 surface_scanner.py -d main-domains.txt --output-dir my_results
```

## 📊 Output Structure

```
scan_results_[timestamp]/
├── subdomains/           # Subdomain enumeration results
│   ├── crtsh_subdomains.txt
│   ├── subfinder_results.txt
│   ├── name_variations.txt
│   └── resolved_domains.txt
├── urls/                 # URL discovery results
│   ├── waybackurls.txt
│   ├── gau_urls.txt
│   ├── all_urls.txt
│   └── live_urls.txt
├── dorks/               # GitHub and Google dorks
│   ├── github_dorks.txt
│   └── google_dorks.txt
├── parameters/          # Parameter discovery
│   └── discovered_params.txt
├── directories/         # Directory bruteforce results
│   └── [domain]/
│       ├── ffuf_common.txt
│       ├── ffuf_big.txt
│       └── ffuf_api.txt
└── sensitive_files/     # Sensitive file check results
    └── sensitive_files.txt
```

## 🔧 Requirements

- Python 3.7+
- Go 1.16+
- Git
- GitHub CLI (gh)

Required tools (auto-installed):
- subfinder
- waybackurls
- gau
- httpx
- ffuf
- dnsx
- arjun
- uro

## ⚙️ Configuration

The tool uses various configuration files and wordlists:
- SecLists for directory bruteforcing
- Custom patterns for sensitive files
- Pre-configured dorks for GitHub scanning
- Parameter wordlists for discovery

## 🔒 Security Considerations

- Always ensure you have proper authorization before scanning
- Respect rate limits and robots.txt
- Be mindful of aggressive scanning patterns
- Handle sensitive information appropriately
- Follow responsible disclosure practices

## 🛡️ Rate Limiting

The tool implements rate limiting for:
- GitHub API requests
- DNS queries
- HTTP requests
- Directory bruteforcing

## 🐛 Troubleshooting

Common issues and solutions:

1. **GitHub Authentication**
```bash
gh auth login
# Follow the prompts
```

2. **Tool Installation Issues**
```bash
# Reinstall tools
./install.sh --force
```

3. **Permission Issues**
```bash
chmod +x install.sh
sudo ./install.sh  # If needed
```

## 📝 License

[MIT License](LICENSE)

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## 🔄 Updates

```bash
git pull origin main
./install.sh --update
```

## ⚠️ Disclaimer

This tool is for security research purposes only. Always ensure you have proper authorization before scanning any systems or networks.
