# 🔥 Elite OSINT Bug Hunting Workflow - Red Team Style

## 🎯 Target Reconnaissance & Intelligence Gathering

### Domain Enumeration (Free Elite Techniques)

**Certificate Transparency Logs:**
```bash
# crt.sh se subdomain nikalna
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# SecurityTrails API (Free tier)
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" -H "APIKEY: YOUR_FREE_API_KEY"

# VirusTotal API
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_FREE_API&domain=target.com"
```

**Advanced Subdomain Discovery:**
```bash
# Subfinder (Free tool)
subfinder -d target.com -silent | tee subdomains.txt

# Assetfinder
assetfinder --subs-only target.com | tee -a subdomains.txt

# Amass (Free)
amass enum -passive -d target.com -o amass_results.txt

# DNS Bruteforcing
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
```

### ASN & IP Range Discovery
```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS15169' | grep -Eo "([0-9.]+){4}/[0-9]+"

# BGP.he.net se IP ranges
curl -s "https://bgp.he.net/AS15169#_prefixes" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+'

# Hurricane Electric BGP Toolkit
curl -s "https://bgp.he.net/search?search%5Bsearch%5D=target.com&commit=Search"
```

## 🔍 Advanced Google Dorking & Search Engine Intelligence

### Elite Google Dorks Collection

**Sensitive File Exposure:**
```
site:target.com filetype:pdf | filetype:doc | filetype:xls | filetype:ppt
site:target.com filetype:sql | filetype:db | filetype:dbf | filetype:mdb
site:target.com filetype:log | filetype:bak | filetype:old | filetype:backup
site:target.com filetype:env | filetype:config | filetype:ini | filetype:conf
site:target.com "index of" | "directory listing" | "parent directory"
site:target.com intext:"password" | intext:"username" | intext:"login"
site:target.com inurl:admin | inurl:administrator | inurl:login | inurl:dashboard
site:target.com "access denied for user" | "mysql error" | "sql syntax"
site:target.com "Warning: mysql_" | "Warning: Cannot modify" | "Fatal error"
```

**API & Development Environment Discovery:**
```
site:target.com inurl:api | inurl:v1 | inurl:v2 | inurl:rest | inurl:graphql
site:target.com "swagger" | "api documentation" | "postman" | "insomnia"
site:target.com inurl:dev | inurl:test | inurl:staging | inurl:beta | inurl:demo
site:target.com "phpinfo()" | "server-status" | "server-info"
site:target.com ".git" | ".svn" | ".env" | "composer.json" | "package.json"
```

**Advanced Bing & DuckDuckGo Dorks:**
```
# Bing specific
site:target.com (ext:doc OR ext:docx OR ext:pdf OR ext:rtf OR ext:sxw OR ext:psw OR ext:ppt OR ext:pptx OR ext:pps OR ext:csv)

# DuckDuckGo specific  
site:target.com "confidential" OR "internal use only" OR "not for distribution"
```

### GitHub & Code Repository Hunting
```bash
# GitHub Dorking
"target.com" password
"target.com" api_key OR apikey OR api-key
"target.com" secret_key OR secretkey OR secret-key
"target.com" access_token OR accesstoken OR access-token
"target.com" config OR configuration
"target.com" database OR db_password OR dbpassword
"target.com" smtp OR email OR mail
"target.com" aws_access_key OR aws_secret
"target.com" private_key OR privatekey OR private-key

# GitLab, Bitbucket similar searches
# Use same dorks on different platforms
```

## ☁️ Cloud Storage & Infrastructure Hunting

### AWS S3 Bucket Enumeration
```bash
# S3 bucket discovery
aws s3 ls s3://target-company
aws s3 ls s3://target-backup
aws s3 ls s3://target-dev
aws s3 ls s3://target-prod
aws s3 ls s3://target-staging
aws s3 ls s3://target-assets
aws s3 ls s3://target-logs
aws s3 ls s3://target-data

# Bucket permission testing
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request
aws s3 sync s3://bucket-name . --no-sign-request

# S3Scanner tool
python s3scanner.py sites.txt
```

### Google Cloud Storage
```bash
# GCS bucket discovery
gsutil ls gs://target-company
gsutil ls gs://target-backup
gsutil ls gs://target-dev

# Permission testing
gsutil ls gs://bucket-name
gsutil cp test.txt gs://bucket-name/
```

### Azure Blob Storage
```bash
# Azure container discovery
https://target.blob.core.windows.net/container-name?restype=container&comp=list
https://target.blob.core.windows.net/backup?restype=container&comp=list
https://target.blob.core.windows.net/dev?restype=container&comp=list
```

## 🌐 Shodan, Censys & IoT Device Discovery

### Elite Shodan Queries
```
# Basic target discovery
org:"Target Company"
ssl:"target.com"
hostname:"target.com"

# Exposed databases
"MongoDB Server Information" port:27017
"mysql" port:3306 "target.com"
"PostgreSQL" port:5432 "target.com"
"redis" port:6379 "target.com"

# Web applications & services
"Apache" "target.com" port:80,443,8080,8443
"nginx" "target.com" port:80,443
"IIS" "target.com" port:80,443

# IoT & Industrial devices
"Schneider Electric" "target.com"
"Siemens" "target.com"
"Allen Bradley" "target.com"
"default password" "target.com"

# Exposed panels
"admin" "login" "target.com"
"dashboard" "target.com"
"phpmyadmin" "target.com"
"grafana" "target.com"
"jenkins" "target.com"

# VPN & Remote access
"openvpn" "target.com"
"rdp" port:3389 "target.com"
"vnc" port:5900 "target.com"
"ssh" port:22 "target.com"

# Cloud services
"aws" "target.com"
"amazon" "target.com"
"docker" "target.com"
"kubernetes" "target.com"
```

### Censys Queries
```
# Certificate-based discovery
parsed.names: target.com
parsed.subject.common_name: target.com
parsed.extensions.subject_alt_name.dns_names: target.com

# Service discovery
services.service_name: HTTP and parsed.names: target.com
services.service_name: HTTPS and parsed.names: target.com
services.port: 22 and parsed.names: target.com
```

### ZoomEye Queries
```
# Basic searches
site:target.com
ssl:target.com
hostname:target.com

# Service specific
app:"Apache httpd" +site:target.com
app:"nginx" +site:target.com
app:"Microsoft IIS" +site:target.com
```

### FOFA Queries (Chinese Infrastructure)
```
# Basic discovery
domain="target.com"
cert="target.com"
title="target"

# Service discovery
app="Apache" && domain="target.com"
app="nginx" && domain="target.com"
port="3389" && domain="target.com"
```

## 🕵️ Deep Web & Dark Web Intelligence

### Pastebin & Code Leak Hunting
```bash
# Pastebin search
curl -s "https://psbdmp.ws/api/search/target.com" | jq

# GitHub secret scanning
python truffleHog.py --regex --entropy=False https://github.com/target/repo

# GitLab scanning
python gitGraber.py -k wordlists/keywords.txt -q target.com

# Pastehunter
python pastehunter.py --keyword "target.com"
```

### Social Media Intelligence
```bash
# LinkedIn employee enumeration
python linkedin2username.py target-company

# Twitter OSINT
python twint -s "target.com" --limit 1000

# Instagram OSINT  
python osintgram.py target_username

# Facebook OSINT
python facebook-scraper target_page
```

## 🔧 Advanced Technical Reconnaissance

### Port Scanning & Service Enumeration
```bash
# Nmap comprehensive scan
nmap -sS -sV -sC -O -A -T4 -p- target.com

# Masscan for large ranges
masscan -p1-65535 target.com --rate=1000

# Service-specific scans
nmap --script http-enum target.com
nmap --script ssl-enum-ciphers target.com
nmap --script smb-enum-shares target.com
```

### SSL/TLS Certificate Analysis
```bash
# Certificate transparency
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[].name_value' | sort -u

# SSL Labs API
curl -s "https://api.ssllabs.com/api/v3/analyze?host=target.com"

# Certificate details
openssl s_client -connect target.com:443 -servername target.com
```

### DNS Analysis
```bash
# DNS enumeration
dig target.com ANY
dig @8.8.8.8 target.com ANY
dig axfr target.com @ns1.target.com

# DNS bruteforcing
dnsrecon -d target.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Reverse DNS
dnsrecon -r 192.168.1.0/24
```

## 🛠️ Free Elite Tools Collection

### Essential Free Tools
```bash
# Subdomain enumeration
- Subfinder
- Assetfinder  
- Amass
- Knockpy
- Sublist3r

# Directory/Content discovery
- Gobuster
- Dirb
- Dirsearch
- Ffuf
- Wfuzz

# Web application testing
- Burp Suite Community
- OWASP ZAP
- Nikto
- Whatweb
- Wappalyzer

# Network scanning
- Nmap
- Masscan
- Zmap
- Unicornscan

# OSINT tools
- theHarvester
- Maltego CE
- Spiderfoot
- Recon-ng
- Shodan CLI
```

### Advanced Automation Scripts
```bash
#!/bin/bash
# Elite recon automation script

TARGET=$1
echo "[+] Starting elite recon for $TARGET"

# Subdomain discovery
echo "[+] Subdomain enumeration..."
subfinder -d $TARGET -silent > subdomains.txt
assetfinder --subs-only $TARGET >> subdomains.txt
amass enum -passive -d $TARGET >> subdomains.txt
sort -u subdomains.txt > final_subdomains.txt

# Port scanning
echo "[+] Port scanning..."
nmap -sS -T4 -iL final_subdomains.txt -oN nmap_results.txt

# Directory bruteforcing
echo "[+] Directory discovery..."
while read subdomain; do
    gobuster dir -u https://$subdomain -w /usr/share/wordlists/dirb/common.txt -o ${subdomain}_dirs.txt
done < final_subdomains.txt

# Screenshot taking
echo "[+] Taking screenshots..."
python EyeWitness.py -f final_subdomains.txt --web

echo "[+] Recon completed!"
```

## 🎯 Advanced Search Techniques

### Multi-Platform Dorking Strategy
```
# Google Advanced
site:target.com (inurl:admin OR inurl:administrator OR inurl:moderator OR inurl:controlpanel OR inurl:adminarea OR inurl:adminpanel OR inurl:admincontrol OR inurl:admincp OR inurl:adminweb OR inurl:administratorlogin OR inurl:admin_area OR inurl:panel-administracion OR inurl:instadmin OR inurl:memberadmin OR inurl:administratorlogin OR inurl:adm OR inurl:admin/account.php OR inurl:admin/index.php OR inurl:admin/login.php OR inurl:admin/admin.php OR inurl:admin_area/admin.php OR inurl:admin_area/login.php OR inurl:siteadmin/login.php OR inurl:siteadmin/index.php OR inurl:siteadmin/login.html OR inurl:admin/account.html OR inurl:admin/index.html OR inurl:admin/login.html OR inurl:admin/admin.html)

# Bing specific searches
site:target.com (filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx OR filetype:pdf OR filetype:sql OR filetype:txt OR filetype:csv OR filetype:xml OR filetype:conf OR filetype:cnf OR filetype:reg OR filetype:inf OR filetype:rdp OR filetype:cfg OR filetype:txt OR filetype:ora OR filetype:ini OR filetype:env)

# DuckDuckGo privacy-focused
site:target.com ("access denied" OR "403 forbidden" OR "401 unauthorized" OR "directory listing" OR "index of" OR "parent directory")
```

### GitHub Advanced Searches
```
# API keys & secrets
"target.com" AND ("api_key" OR "apikey" OR "api-key" OR "secret_key" OR "secretkey" OR "secret-key" OR "access_token" OR "accesstoken" OR "access-token")

# Database credentials  
"target.com" AND ("db_password" OR "dbpassword" OR "database_password" OR "mysql_password" OR "postgres_password" OR "mongodb_password")

# Configuration files
"target.com" AND (filename:config OR filename:.env OR filename:settings OR filename:database OR filename:db)

# AWS credentials
"target.com" AND ("aws_access_key_id" OR "aws_secret_access_key" OR "AWS_ACCESS_KEY_ID" OR "AWS_SECRET_ACCESS_KEY")
```

## 📊 Reporting & Documentation

### Elite Report Structure
```markdown
# OSINT Reconnaissance Report - [Target]

## Executive Summary
- Target overview
- Key findings summary
- Risk assessment
- Recommendations

## Methodology
- Tools used
- Techniques employed
- Timeframe
- Scope limitations

## Findings

### 1. Domain & Subdomain Discovery
- Total subdomains found: X
- Live subdomains: X
- Interesting subdomains:
  - dev.target.com (Development environment)
  - admin.target.com (Admin panel)
  - api.target.com (API endpoints)

### 2. Exposed Services & Ports
- Open ports summary
- Vulnerable services
- Misconfigurations

### 3. Information Disclosure
- Sensitive files found
- Configuration exposures
- Database leaks
- API documentation

### 4. Cloud Infrastructure
- S3 buckets discovered
- Permissions issues
- Exposed data

### 5. Social Engineering Vectors
- Employee information
- Email patterns
- Social media presence

## Risk Assessment
- Critical: X findings
- High: X findings  
- Medium: X findings
- Low: X findings

## Recommendations
1. Immediate actions required
2. Security improvements
3. Monitoring suggestions

## Appendix
- Complete subdomain list
- Port scan results
- Screenshots
- Tool outputs
```

## 🔥 Pro Tips for Elite Bug Hunters

### Advanced Techniques
1. **Certificate Transparency Monitoring**: Set up alerts for new certificates
2. **Passive DNS Analysis**: Use historical DNS data
3. **ASN Monitoring**: Track IP range changes
4. **Social Media Monitoring**: Employee information gathering
5. **Dark Web Monitoring**: Breach data analysis
6. **Mobile App Analysis**: APK/IPA reverse engineering
7. **IoT Device Discovery**: Specialized Shodan queries
8. **Cloud Misconfiguration**: Automated bucket scanning

### Automation & Scaling
```bash
# Create monitoring scripts
#!/bin/bash
# Daily monitoring script
while true; do
    # Check for new subdomains
    subfinder -d target.com -silent > today_subs.txt
    diff yesterday_subs.txt today_subs.txt > new_subs.txt
    
    # Alert if new subdomains found
    if [ -s new_subs.txt ]; then
        echo "New subdomains found!" | mail -s "Alert" your@email.com
    fi
    
    mv today_subs.txt yesterday_subs.txt
    sleep 86400  # 24 hours
done
```

### Legal & Ethical Guidelines
- Always get proper authorization
- Respect rate limits and ToS
- Don't access unauthorized data
- Report findings responsibly
- Document everything properly
- Follow responsible disclosure

---

**Remember**: Ye workflow sirf educational aur authorized testing ke liye hai. Hamesha legal boundaries ke andar rehna aur proper authorization lena zaroori hai! 🔒

**Happy Hunting! 🎯**