# 🔥 Elite OSINT Bug Hunting Toolkit - Usage Guide

## 📋 Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Individual Tools](#individual-tools)
4. [Master Automation](#master-automation)
5. [Manual Techniques](#manual-techniques)
6. [Pro Tips](#pro-tips)
7. [Legal & Ethical Guidelines](#legal--ethical-guidelines)

## 🚀 Installation

### Prerequisites
```bash
# Python 3.7+ required
python3 --version

# Install required packages
pip3 install requests concurrent.futures pathlib argparse
```

### Optional Tools (Recommended)
```bash
# Nmap for port scanning
sudo apt install nmap

# Git for repository cloning
sudo apt install git

# Additional tools
sudo apt install curl wget jq
```

## ⚡ Quick Start

### 1. Master Automation (Recommended)
```bash
# Run complete OSINT reconnaissance
python3 elite_osint_master.py example.com

# With GitHub token for better results
python3 elite_osint_master.py example.com -g ghp_xxxxxxxxxxxxxxxxxxxx

# Skip specific modules
python3 elite_osint_master.py example.com --skip port_scanning github_secrets_hunting

# Custom output directory
python3 elite_osint_master.py example.com -o my_results_folder
```

### 2. Quick Individual Scans
```bash
# Subdomain enumeration
python3 elite_recon_automation.py example.com

# Cloud bucket hunting
python3 cloud_bucket_hunter.py example.com

# GitHub secrets discovery
python3 github_secrets_hunter.py example.com

# Admin panel hunting
python3 admin_panel_hunter.py example.com
```

## 🛠️ Individual Tools

### 1. Elite Recon Automation
**Purpose**: Comprehensive subdomain discovery and reconnaissance

```bash
# Basic usage
python3 elite_recon_automation.py example.com

# With VirusTotal API key
python3 elite_recon_automation.py example.com vt_api_key_here

# Output files:
# - example.com_subdomains.txt
# - example.com_alive_subdomains.txt
# - example.com_google_dorks.txt
# - example.com_github_dorks.txt
# - example.com_shodan_queries.txt
# - example.com_results.json
```

**Features**:
- Certificate Transparency logs (crt.sh)
- HackerTarget API
- ThreatCrowd API
- VirusTotal API (optional)
- Live subdomain verification
- Google/GitHub/Shodan query generation

### 2. Cloud Bucket Hunter
**Purpose**: Discover exposed cloud storage buckets

```bash
# Hunt for cloud buckets
python3 cloud_bucket_hunter.py example.com

# Output files:
# - example.com_cloud_buckets.json
# - example.com_cloud_buckets.txt
```

**Supported Platforms**:
- AWS S3 Buckets
- Google Cloud Storage
- Azure Blob Storage
- DigitalOcean Spaces

**Common Bucket Patterns Tested**:
- company-backup, company-dev, company-prod
- company-assets, company-logs, company-data
- 100+ naming variations automatically generated

### 3. GitHub Secrets Hunter
**Purpose**: Automated GitHub dorking for sensitive data

```bash
# Basic GitHub secrets hunting
python3 github_secrets_hunter.py example.com

# With GitHub token (recommended)
python3 github_secrets_hunter.py example.com ghp_xxxxxxxxxxxxxxxxxxxx

# Output files:
# - example.com_github_secrets.json
# - example.com_github_secrets.txt
# - example.com_github_urls.txt
```

**What it finds**:
- API keys and tokens
- Database credentials
- AWS/GCP/Azure keys
- Private keys and certificates
- Configuration files
- Environment variables

### 4. Admin Panel Hunter
**Purpose**: Discover admin panels and login pages

```bash
# Single target
python3 admin_panel_hunter.py example.com

# Multiple targets
python3 admin_panel_hunter.py example.com test.com demo.org

# From file
python3 admin_panel_hunter.py -f targets.txt

# Output files:
# - admin_panels_TIMESTAMP.json
# - admin_panels_TIMESTAMP.txt
# - admin_urls_TIMESTAMP.txt
```

**Detection Capabilities**:
- 500+ admin panel paths
- CMS admin areas (WordPress, Joomla, Drupal)
- Server management panels (cPanel, Plesk, Webmin)
- Development tools (Jenkins, GitLab, Grafana)
- Database interfaces (phpMyAdmin, Adminer)

## 🎯 Master Automation

### Command Line Options
```bash
python3 elite_osint_master.py [OPTIONS] TARGET

Options:
  -o, --output DIR          Custom output directory
  -g, --github-token TOKEN  GitHub API token
  --skip MODULE [MODULE...] Skip specific modules

Modules:
  - subdomain_enumeration   Subdomain discovery
  - cloud_bucket_hunting    Cloud storage hunting
  - github_secrets_hunting  GitHub secrets discovery
  - admin_panel_hunting     Admin panel discovery
  - dork_generation        Google/Shodan dorks
  - port_scanning          Basic port scanning
```

### Example Workflows

#### Full Reconnaissance
```bash
# Complete OSINT with all modules
python3 elite_osint_master.py example.com -g YOUR_GITHUB_TOKEN
```

#### Quick Assessment
```bash
# Skip time-consuming modules
python3 elite_osint_master.py example.com --skip port_scanning github_secrets_hunting
```

#### Stealth Mode
```bash
# Only passive reconnaissance
python3 elite_osint_master.py example.com --skip port_scanning admin_panel_hunting
```

## 📖 Manual Techniques

### 1. Google Dorking
Use the generated `elite_google_dorks.txt` file:

```bash
# Example dorks for example.com:
site:example.com filetype:pdf
site:example.com "index of"
site:example.com inurl:admin
site:example.com "password"
site:example.com filetype:env
```

**Pro Tip**: Use different search engines (Google, Bing, DuckDuckGo) for varied results.

### 2. Shodan/Censys Queries
Use the generated `elite_shodan_censys_queries.txt` file:

```bash
# Shodan examples:
hostname:"example.com"
ssl:"example.com"
org:"Example Company"

# Censys examples:
parsed.names: example.com
services.service_name: HTTP and parsed.names: example.com
```

### 3. Manual Verification
Always manually verify automated findings:

1. **Subdomains**: Check if they're actually live and accessible
2. **Admin Panels**: Verify they're real admin interfaces
3. **Cloud Buckets**: Test actual permissions and content
4. **GitHub Secrets**: Validate if credentials are still active

## 💡 Pro Tips

### 1. Rate Limiting & Stealth
```bash
# Use VPN to rotate IP addresses
# Add delays between requests
# Use different User-Agent strings
# Respect robots.txt and rate limits
```

### 2. API Keys & Tokens
```bash
# Get free API keys for better results:
# - GitHub Personal Access Token
# - VirusTotal API Key
# - SecurityTrails API Key
# - Shodan API Key (optional)
```

### 3. Automation & Monitoring
```bash
# Set up cron jobs for continuous monitoring
0 2 * * * /usr/bin/python3 /path/to/elite_osint_master.py example.com

# Monitor for new subdomains
# Alert on new admin panels
# Track cloud bucket changes
```

### 4. Data Organization
```bash
# Organize results by date
mkdir results_$(date +%Y%m%d)

# Keep historical data
# Compare results over time
# Track changes and new discoveries
```

### 5. Integration with Other Tools
```bash
# Feed subdomains to other tools:
cat example.com_subdomains.txt | httpx -silent | nuclei

# Use discovered URLs with:
# - Burp Suite
# - OWASP ZAP
# - Custom scripts
```

## 🔍 Understanding Results

### 1. Subdomain Results
- **Total Subdomains**: All discovered subdomains
- **Alive Subdomains**: Responding subdomains with HTTP status
- **Interesting Subdomains**: dev, admin, api, staging, etc.

### 2. Cloud Bucket Results
- **Public Read**: Bucket contents are publicly accessible
- **Access Denied**: Bucket exists but access is restricted
- **Files Count**: Number of files in accessible buckets

### 3. GitHub Secrets Results
- **High Priority**: API keys, database credentials, private keys
- **Medium Priority**: Configuration files, tokens
- **Low Priority**: General mentions, comments

### 4. Admin Panel Results
- **Status 200**: Accessible admin panel
- **Status 401/403**: Protected admin panel (authentication required)
- **Platform Detection**: Identified CMS or application type

## 📊 Report Analysis

### HTML Report Sections
1. **Executive Summary**: High-level statistics
2. **Scan Results**: Module-by-module results
3. **Generated Files**: List of all output files
4. **Next Steps**: Recommended manual verification steps

### Key Metrics to Review
- Number of live subdomains discovered
- Admin panels found (especially status 200)
- Cloud buckets with public access
- GitHub repositories with sensitive data
- High-value targets for further testing

## ⚠️ Legal & Ethical Guidelines

### ✅ Authorized Testing Only
- Only test domains you own or have explicit permission to test
- Get written authorization before testing third-party systems
- Respect scope limitations and boundaries
- Follow responsible disclosure practices

### ✅ Rate Limiting & Respect
- Don't overwhelm target systems with requests
- Respect robots.txt and terms of service
- Use reasonable delays between requests
- Monitor your impact on target systems

### ✅ Data Handling
- Secure storage of discovered sensitive data
- Don't share or publish sensitive findings publicly
- Follow data protection regulations (GDPR, etc.)
- Delete sensitive data when no longer needed

### ❌ Prohibited Activities
- Testing without authorization
- Accessing unauthorized systems or data
- Causing disruption or damage
- Violating terms of service
- Sharing sensitive data publicly

## 🆘 Troubleshooting

### Common Issues

#### 1. "No results found"
```bash
# Possible causes:
# - Target has strong security posture
# - Rate limiting or IP blocking
# - Network connectivity issues
# - API key limitations

# Solutions:
# - Try different IP address/VPN
# - Use API keys for higher limits
# - Increase delays between requests
# - Try manual verification
```

#### 2. "Permission denied" errors
```bash
# Possible causes:
# - Insufficient file permissions
# - Missing dependencies
# - Network restrictions

# Solutions:
chmod +x *.py
pip3 install -r requirements.txt
sudo apt update && sudo apt install python3-pip
```

#### 3. "Rate limited" messages
```bash
# Solutions:
# - Use API keys
# - Increase delays
# - Use VPN/proxy
# - Run during off-peak hours
```

### Getting Help
1. Check log files in output directory
2. Run with verbose output
3. Verify all dependencies are installed
4. Test with a known working target first

## 🔄 Updates & Maintenance

### Keeping Tools Updated
```bash
# Update wordlists and patterns regularly
# Monitor for new admin panel paths
# Update API endpoints as they change
# Add new cloud storage providers
```

### Contributing
- Report bugs and issues
- Suggest new features
- Share additional dorks and patterns
- Improve documentation

---

**Happy Hunting! 🎯🔥**

Remember: Use these tools responsibly and only on authorized targets. The goal is to improve security, not to cause harm.