import subprocess
import os
import sys
import json
import signal
import platform
import argparse
import itertools
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

import requests  # External dependency

def signal_handler(sig, frame):
    print("\n[!] Ctrl+C detected. Gracefully exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_examples():
    examples = """
Examples:
    # Run full scan
    python3 surface_scanner.py -d domains.txt

    # Only run GitHub dorking
    python3 surface_scanner.py -d domains.txt --github-dork

    # Only run subdomain discovery
    python3 surface_scanner.py -d domains.txt --subdomain

    # Continue from step 3 (URL discovery)
    python3 surface_scanner.py -d domains.txt --from-step 3

    # Specify custom output directory
    python3 surface_scanner.py -d domains.txt --output-dir my_scan_results
    """
    print(examples)

class SurfaceScanner:
    def __init__(self, domain_list_path):
        self.domain_list_path = domain_list_path
        self.results_dir = "scan_results_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        self.subdomains_dir = os.path.join(self.results_dir, "subdomains")
        self.urls_dir = os.path.join(self.results_dir, "urls")
        self.dorks_dir = os.path.join(self.results_dir, "dorks")
        self.params_dir = os.path.join(self.results_dir, "parameters")
        self.dirs_dir = os.path.join(self.results_dir, "directories")
        self.sensitive_dir = os.path.join(self.results_dir, "sensitive_files")
        self.domains = self._load_domains()
        self._setup_directories()

    def _setup_directories(self):
        """Create necessary directories for results"""
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.subdomains_dir, exist_ok=True)
        os.makedirs(self.urls_dir, exist_ok=True)
        os.makedirs(self.dorks_dir, exist_ok=True)
        os.makedirs(self.params_dir, exist_ok=True)
        os.makedirs(self.dirs_dir, exist_ok=True)
        os.makedirs(self.sensitive_dir, exist_ok=True)

    def _load_domains(self):
        if not os.path.exists(self.domain_list_path):
            raise FileNotFoundError(f"Domain list file {self.domain_list_path} not found!")
        with open(self.domain_list_path, 'r') as f:
            return f.read().splitlines()

    def _run_command(self, command, output_file=None):
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            if stderr:
                print(f"[-] Error: {stderr}")
            
            if output_file and stdout:
                with open(output_file, 'w') as f:
                    f.write(stdout)
            
            return stdout.splitlines() if stdout else []
            
        except Exception as e:
            print(f"[-] Command failed: {str(e)}")
            return []

    def _merge_files(self, input_files, output_file):
        """Merge multiple files and remove duplicates"""
        all_lines = set()
        for file in input_files:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    all_lines.update(f.read().splitlines())
        
        if all_lines:
            with open(output_file, 'w') as f:
                f.write('\n'.join(sorted(all_lines)))
            print(f"[+] Merged results saved to: {output_file}")
            return len(all_lines)
        return 0

    def generate_name_variations(self, domain):
        """Generate common name variations for a domain"""
        base_name = domain.split('.')[0]
        suffixes = ['-dev', '-stage', '-staging', '-test', '-uat', '-prod',
                   '-api', '-admin', '-portal', '-app', '-mobile', '-web']
        variations = [f"{base_name}{suffix}" for suffix in suffixes]
        variations.extend([f"dev-{base_name}", f"stage-{base_name}", f"test-{base_name}"])
        return variations

    def run_crtsh(self):
        """Fetch subdomains from crt.sh"""
        print("\n[+] Fetching subdomains from crt.sh...")
        output_file = os.path.join(self.subdomains_dir, "crtsh_subdomains.txt")
        all_results = set()

        for domain in self.domains:
            print(f"[*] Querying crt.sh for {domain}")
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            try:
                response = requests.get(url)
                if response.ok:
                    data = response.json()
                    for entry in data:
                        all_results.add(entry['name_value'].lower())
            except Exception as e:
                print(f"[-] Error querying crt.sh for {domain}: {str(e)}")

        if all_results:
            with open(output_file, 'w') as f:
                f.write('\n'.join(sorted(all_results)))
            print(f"[+] Found {len(all_results)} subdomains from crt.sh")

    def run_subfinder(self):
        """Run subfinder for subdomain enumeration"""
        print("\n[+] Starting subfinder scan...")
        output_file = os.path.join(self.subdomains_dir, "subfinder_results.txt")
        
        for domain in self.domains:
            print(f"[*] Running subfinder for {domain}")
            self._run_command(f'subfinder -d {domain} -silent', output_file)

    def run_name_variations(self):
        """Check for common subdomain name variations"""
        print("\n[+] Checking common name variations...")
        output_file = os.path.join(self.subdomains_dir, "name_variations.txt")
        all_variations = set()

        for domain in self.domains:
            domain_parts = domain.split('.')
            tld = '.'.join(domain_parts[1:])
            variations = self.generate_name_variations(domain)
            all_variations.update(f"{v}.{tld}" for v in variations)

        if all_variations:
            with open(output_file, 'w') as f:
                f.write('\n'.join(sorted(all_variations)))
            print(f"[+] Generated {len(all_variations)} name variations")

    def run_dnsx(self):
        """Resolve discovered subdomains"""
        print("\n[+] Starting DNS resolution with dnsx...")
        merged_file = os.path.join(self.subdomains_dir, "all_subdomains.txt")
        output_file = os.path.join(self.subdomains_dir, "resolved_domains.txt")
        
        # Merge all subdomain files
        subdomain_files = [
            os.path.join(self.subdomains_dir, f)
            for f in ["crtsh_subdomains.txt", "subfinder_results.txt", "name_variations.txt"]
        ]
        
        total = self._merge_files(subdomain_files, merged_file)
        print(f"[+] Total unique subdomains to resolve: {total}")
        
        if os.path.exists(merged_file):
            self._run_command(
                f'dnsx -l {merged_file} -a -resp -silent',
                output_file
            )

    def run_url_discovery(self):
        """Discover URLs using multiple tools"""
        print("\n[+] Starting URL discovery...")
        wayback_file = os.path.join(self.urls_dir, "waybackurls.txt")
        gau_file = os.path.join(self.urls_dir, "gau_urls.txt")
        
        resolved_domains = os.path.join(self.subdomains_dir, "resolved_domains.txt")
        if not os.path.exists(resolved_domains):
            print("[-] No resolved domains found. Using original domain list.")
            domains = self.domains
        else:
            with open(resolved_domains) as f:
                domains = [line.split()[0] for line in f.readlines()]

        # Run waybackurls
        print("[*] Running waybackurls...")
        for domain in domains:
            self._run_command(f'echo {domain} | waybackurls', wayback_file)

        # Run gau
        print("[*] Running gau...")
        for domain in domains:
            self._run_command(f'echo {domain} | gau --blacklist png,jpg,gif,css,js,woff,woff2,svg', gau_file)

        # Merge URL results
        merged_file = os.path.join(self.urls_dir, "all_urls.txt")
        total = self._merge_files([wayback_file, gau_file], merged_file)
        print(f"[+] Total unique URLs discovered: {total}")

    def run_url_processing(self):
        """Process and filter discovered URLs"""
        print("\n[+] Processing discovered URLs...")
        input_file = os.path.join(self.urls_dir, "all_urls.txt")
        processed_file = os.path.join(self.urls_dir, "processed_urls.txt")
        live_urls_file = os.path.join(self.urls_dir, "live_urls.txt")

        if os.path.exists(input_file):
            # Use uro to optimize URLs
            self._run_command(f'cat {input_file} | /Users/navid/Library/Python/3.9/bin/uro > {processed_file}')
            
            # Probe URLs with httpx
            print("[*] Probing URLs with httpx...")
            self._run_command(
                f'cat {processed_file} | httpx -silent -status-code -title -follow-redirects -mc 200,201,301,302,307,401,403,405',
                live_urls_file
            )

    def run_github_dorks(self):
        """Search GitHub for sensitive information"""
        print("\n[+] Starting GitHub dorking...")
        output_file = os.path.join(self.dorks_dir, "github_dorks.txt")
        
        # Common GitHub dorks for sensitive information
        dorks = [
            'password', 'secret', 'credential', 'token', 'apikey', 'api_key',
            'aws_access', 'aws_secret', 'ssh_key', 'private_key', 'dbpasswd',
            'client_secret', 'api_token', '.env', 'config', '.npmrc', '.dockercfg'
        ]
        
        for domain in self.domains:
            print(f"[*] Searching GitHub for {domain}")
            for dork in dorks:
                # Using gh cli if available, otherwise use GitHub API
                self._run_command(
                    f'gh search code "{dork} {domain}" --limit 100',
                    output_file
                )

    def run_google_dorks(self):
        """Run Google dorks for sensitive information"""
        print("\n[+] Starting Google dorking...")
        output_file = os.path.join(self.dorks_dir, "google_dorks.txt")
        
        dorks = [
            'site:{domain} ext:php inurl:admin',
            'site:{domain} ext:log',
            'site:{domain} inurl:login',
            'site:{domain} filetype:env OR filetype:yml OR filetype:config',
            'site:{domain} inurl:signup OR inurl:register',
            'site:{domain} inurl:api OR inurl:apis',
            'site:{domain} ext:sql OR ext:db OR ext:backup',
            'site:{domain} inurl:wp-admin OR inurl:wp-content'
        ]
        
        # Write dorks to file for manual execution (due to Google's restrictions)
        with open(output_file, 'w') as f:
            for domain in self.domains:
                for dork in dorks:
                    f.write(dork.format(domain=domain) + '\n')
        
        print(f"[+] Google dorks saved to {output_file}")

    def run_param_discovery(self):
        """Discover parameters using Arjun"""
        print("\n[+] Starting parameter discovery with Arjun...")
        output_file = os.path.join(self.params_dir, "discovered_params.txt")
        live_urls = os.path.join(self.urls_dir, "live_urls.txt")
        
        if not os.path.exists(live_urls):
            print("[-] No live URLs found. Skipping parameter discovery.")
            return
            
        with open(live_urls) as f:
            urls = [line.split()[0] for line in f.readlines()]
            
        for url in urls:
            print(f"[*] Running Arjun on {url}")
            self._run_command(
                f'/Users/navid/Library/Python/3.9/bin/arjun -u {url} -t 10 --stable -f ./SecLists/Discovery/Web-Content/burp-parameter-names.txt',
                os.path.join(self.params_dir, f"params_{urlparse(url).netloc}.json")
            )
        
        # Merge all param files
        param_files = [f for f in os.listdir(self.params_dir) if f.endswith('.json')]
        results = []
        for pfile in param_files:
            with open(os.path.join(self.params_dir, pfile)) as f:
                try:
                    data = json.load(f)
                    if 'params' in data:
                        results.extend(data['params'])
                except:
                    continue
        
        if results:
            with open(output_file, 'w') as f:
                f.write('\n'.join(sorted(set(results))))
            print(f"[+] All discovered parameters saved to {output_file}")

    def run_directory_bruteforce(self):
        """Run directory bruteforcing with ffuf"""
        print("\n[+] Starting directory bruteforcing...")
        wordlists = {
            'common': './SecLists/Discovery/Web-Content/common.txt',
            'big': './SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt',
            'api': './SecLists/Discovery/Web-Content/api/api-endpoints.txt',
            'quickhits': './SecLists/Discovery/Web-Content/quickhits.txt',
            'raft': './SecLists/Discovery/Web-Content/raft-large-directories.txt'
        }
        
        live_urls = os.path.join(self.urls_dir, "live_urls.txt")
        if not os.path.exists(live_urls):
            print("[-] No live URLs found. Skipping directory bruteforce.")
            return
            
        with open(live_urls) as f:
            urls = [line.split()[0] for line in f.readlines()]
            
        for url in urls:
            base_url = url.rstrip('/')
            output_dir = os.path.join(self.dirs_dir, urlparse(url).netloc)
            os.makedirs(output_dir, exist_ok=True)
            
            for wl_name, wordlist in wordlists.items():
                output_file = os.path.join(output_dir, f"ffuf_{wl_name}.txt")
                print(f"[*] Running ffuf on {base_url} with {wl_name} wordlist")
                self._run_command(
                    f'ffuf -u {base_url}/FUZZ -w {wordlist} -mc 200,201,202,203,204,301,302,307,401,403,405 -o {output_file} -of json',
                    None
                )

    def check_sensitive_files(self):
        """Check for sensitive files and directories"""
        print("\n[+] Checking for sensitive files...")
        sensitive_patterns = [ # Extended list of sensitive files
            '.git/config', '.env', 'wp-config.php', 'config.php', 'configuration.php',
            'database.php', 'settings.php', 'composer.json', 'package.json',
            '.htaccess', 'robots.txt', 'sitemap.xml', 'backup/', 'admin/',
            'phpinfo.php', '.svn/entries', '.DS_Store', 'credentials.txt',
            'debug.log', 'error_log', '.aws/credentials', '.ssh/id_rsa'
            '.git/HEAD', '.git/index', '.svn/wc.db', '.hg/store/data',
            'server-status', 'server-info', '.well-known/security.txt',
            'crossdomain.xml', 'clientaccesspolicy.xml', 'php.ini',
            'web.config', '.bash_history', '.zsh_history', '.mysql_history',
            'backup.sql', 'dump.sql', 'database.sql', 'users.sql',
            'phpMyAdmin/', 'phpmyadmin/', 'mysql/', '_admin/', 'administrator/',
            'upload/', 'uploads/', 'backup/', 'backups/', 'tmp/', 'temp/',
            'dev/', 'test/', 'beta/', 'staging/', '.dockerignore', 'Dockerfile',
            'docker-compose.yml', 'jenkins.txt', 'jenkins.xml', 'id_dsa',
            '.idea/', '.vscode/', '.git/', '.svn/', '.hg/', 'CVS/',
            'swagger/index.html', 'api/swagger/', 'api/docs/', 'debug/vars'
        ]
        
        resolved_domains = os.path.join(self.subdomains_dir, "resolved_domains.txt")
        if os.path.exists(resolved_domains):
            with open(resolved_domains) as f:
                domains = [line.split()[0] for line in f.readlines()]
                
            output_file = os.path.join(self.sensitive_dir, "sensitive_files.txt")
            for domain in domains:
                print(f"[*] Checking sensitive files on {domain}")
                for pattern in sensitive_patterns:
                    url = f"https://{domain}/{pattern}"
                    self._run_command(
                        f'curl -sk -m 10 {url} -o /dev/null -w "%{{http_code}} {url}\\n"',
                        output_file
                    )

    def scan(self):
        """Run all scanning modules"""
        print(f"\n{Colors.BOLD}╔══════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.BOLD}║      Enhanced Surface Scanner v1.0        ║{Colors.ENDC}")
        print(f"{Colors.BOLD}╚══════════════════════════════════════════╝{Colors.ENDC}\n")
        
        print(f"{Colors.GREEN}[+] Starting scan for {len(self.domains)} domains{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Results will be saved in: {self.results_dir}{Colors.ENDC}\n")
        
        steps = {
            1: ("Subdomain Discovery", [self.run_crtsh, self.run_subfinder, self.run_name_variations]),
            2: ("DNS Resolution", [self.run_dnsx]),
            3: ("URL Discovery", [self.run_url_discovery, self.run_url_processing]),
            4: ("Dorking", [self.run_github_dorks, self.run_google_dorks]),
            5: ("Parameter Discovery", [self.run_param_discovery]),
            6: ("Content Discovery", [self.run_directory_bruteforce, self.check_sensitive_files])
        }
        
        for step_num, (step_name, functions) in steps.items():
            print(f"\n{Colors.BOLD}Step {step_num}: {step_name}{Colors.ENDC}")
            print("├" + "─" * 50)
            
            try:
                for func in functions:
                    func()
                print(f"{Colors.GREEN}[✓] {step_name} completed{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}[✗] Error in {step_name}: {str(e)}{Colors.ENDC}")
                continue
        
        print(f"\n{Colors.GREEN}[+] Surface scanning completed!{Colors.ENDC}")
        print(f"\n{Colors.BOLD}Results are organized in:{Colors.ENDC}")
        print(f"└── {self.results_dir}/")
        print(f"    ├── {self.subdomains_dir.split('/')[-1]}/")
        print(f"    ├── {self.urls_dir.split('/')[-1]}/")
        print(f"    ├── {self.dorks_dir.split('/')[-1]}/")
        print(f"    ├── {self.params_dir.split('/')[-1]}/")
        print(f"    ├── {self.dirs_dir.split('/')[-1]}/")
        print(f"    └── {self.sensitive_dir.split('/')[-1]}/")

def parse_args():
    parser = argparse.ArgumentParser(
        description='Enhanced Surface Scanner for Bug Bounty Hunting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Steps:
    1. Subdomain Discovery (crt.sh, subfinder, name variations)
    2. DNS Resolution (dnsx)
    3. URL Discovery (waybackurls, gau)
    4. GitHub & Google Dorking
    5. Parameter Discovery (arjun)
    6. Directory Bruteforce (ffuf) & Sensitive Files Check

Note: Use --examples to see usage examples""")
    parser.add_argument('-d', '--domains', default='main-domains.txt',
                      help='File containing list of target domains')
    parser.add_argument('--github-dork', action='store_true',
                      help='Only run GitHub dorking')
    parser.add_argument('--google-dork', action='store_true',
                      help='Only run Google dorking')
    parser.add_argument('--subdomain', action='store_true',
                      help='Only run subdomain discovery')
    parser.add_argument('--urls', action='store_true',
                      help='Only run URL discovery')
    parser.add_argument('--params', action='store_true',
                      help='Only run parameter discovery')
    parser.add_argument('--dirs', action='store_true',
                      help='Only run directory bruteforcing')
    parser.add_argument('--sensitive', action='store_true',
                      help='Only check for sensitive files')
    parser.add_argument('--from-step', type=int, choices=range(1,7),
                      help='Continue from a specific step (1-6)')
    parser.add_argument('--output-dir', type=str,
                      help='Custom output directory name')
    parser.add_argument('--examples', action='store_true',
                      help='Show usage examples')

    args = parser.parse_args()
    
    if args.examples:
        print_examples()
        sys.exit(0)
    
    return args

class ToolInstaller:
    """Handle installation of required tools"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.package_manager = self._detect_package_manager()
    
    def _detect_package_manager(self) -> str:
        """Detect the system's package manager"""
        if self.os_type == "darwin":
            return "brew"
        elif self.os_type == "linux":
            if os.path.exists("/usr/bin/apt"):
                return "apt"
            elif os.path.exists("/usr/bin/yum"):
                return "yum"
            elif os.path.exists("/usr/bin/dnf"):
                return "dnf"
        return ""
    
    def check_tool(self, tool: str) -> bool:
        """Check if a tool is installed"""
        try:
            subprocess.run(f"which {tool}", shell=True, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def install_tool(self, tool: str) -> bool:
        """Install a tool using appropriate method"""
        print(f"{Colors.BLUE}[*] Installing {tool}...{Colors.ENDC}")
        
        if tool == "gh":
            return self.install_github_cli()
        elif tool in ["subfinder", "waybackurls", "gau", "httpx", "ffuf", "dnsx"]:
            return self.install_go_tool(tool)
        elif tool == "arjun":
            return self.install_python_tool(tool)
        elif tool == "uro":
            return self.install_python_tool(tool)
        
        return False
    
    def install_github_cli(self) -> bool:
        """Install GitHub CLI"""
        if self.package_manager == "brew":
            return self._run_command("brew install gh")
        elif self.package_manager in ["apt", "yum", "dnf"]:
            commands = [
                'type -p curl >/dev/null || (sudo apt update && sudo apt install curl -y)',
                'curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg',
                'sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg',
                'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null',
                'sudo apt update',
                'sudo apt install gh -y'
            ]
            return all(self._run_command(cmd) for cmd in commands)
        return False
    
    def install_go_tool(self, tool: str) -> bool:
        """Install a Go-based tool"""
        if not self.check_tool("go"):
            print(f"{Colors.RED}[!] Go is required but not installed. Please install Go first.{Colors.ENDC}")
            return False
        
        tool_map = {
            "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "waybackurls": "github.com/tomnomnom/waybackurls@latest",
            "gau": "github.com/lc/gau/v2/cmd/gau@latest",
            "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "ffuf": "github.com/ffuf/ffuf@latest",
            "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        }
        
        if tool in tool_map:
            return self._run_command(f"go install {tool_map[tool]}")
        return False
    
    def install_python_tool(self, tool: str) -> bool:
        """Install a Python-based tool"""
        return self._run_command(f"pip3 install {tool}")
    
    def _run_command(self, command: str) -> bool:
        """Run a shell command and return success status"""
        try:
            subprocess.run(command, shell=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def check_and_install_tools(self) -> None:
        """Check and install all required tools"""
        required_tools = [
            "gh", "subfinder", "waybackurls", "gau", "httpx",
            "ffuf", "dnsx", "arjun", "uro"
        ]
        
        print(f"{Colors.BOLD}[*] Checking required tools...{Colors.ENDC}")
        for tool in required_tools:
            if not self.check_tool(tool):
                print(f"{Colors.YELLOW}[!] {tool} not found, attempting installation...{Colors.ENDC}")
                if self.install_tool(tool):
                    print(f"{Colors.GREEN}[+] Successfully installed {tool}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[!] Failed to install {tool}{Colors.ENDC}")
            else:
                print(f"{Colors.GREEN}[+] {tool} is installed{Colors.ENDC}")

if __name__ == "__main__":
    args = parse_args()
    
    # Check and install required tools
    installer = ToolInstaller()
    installer.check_and_install_tools()
    
    # Check GitHub authentication
    if not installer.check_tool("gh"):
        print(f"{Colors.RED}[!] GitHub CLI (gh) is required but could not be installed{Colors.ENDC}")
        sys.exit(1)
    
    try:
        subprocess.run("gh auth status", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print(f"{Colors.YELLOW}[!] GitHub CLI not authenticated. Please run 'gh auth login' first{Colors.ENDC}")
        sys.exit(1)
    
    # Initialize scanner
    scanner = SurfaceScanner(args.domains)
    if args.output_dir:
        scanner.results_dir = args.output_dir
        scanner._setup_directories()
    
    # Run specific module if requested
    if args.github_dork:
        scanner.run_github_dorks()
    elif args.google_dork:
        scanner.run_google_dorks()
    elif args.subdomain:
        scanner.run_crtsh()
        scanner.run_subfinder()
        scanner.run_name_variations()
        scanner.run_dnsx()
    elif args.urls:
        scanner.run_url_discovery()
        scanner.run_url_processing()
    elif args.params:
        scanner.run_param_discovery()
    elif args.dirs:
        scanner.run_directory_bruteforce()
    elif args.sensitive:
        scanner.check_sensitive_files()
    else:
        # Run full scan from specified step
        steps = {
            1: [scanner.run_crtsh, scanner.run_subfinder, scanner.run_name_variations],
            2: [scanner.run_dnsx],
            3: [scanner.run_url_discovery, scanner.run_url_processing],
            4: [scanner.run_github_dorks, scanner.run_google_dorks],
            5: [scanner.run_param_discovery],
            6: [scanner.run_directory_bruteforce, scanner.check_sensitive_files]
        }
        
        start_step = args.from_step if args.from_step else 1
        print(f"{Colors.BLUE}[*] Starting scan from step {start_step}{Colors.ENDC}")
        
        for step in range(start_step, 7):
            for func in steps[step]:
                func()
