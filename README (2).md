# 🔥 Elite OSINT Bug Hunting Toolkit

**Complete Red Team OSINT Automation Suite - Free & Open Source**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)](https://github.com/)

## 🎯 Overview

Elite OSINT Bug Hunting Toolkit hai ek comprehensive automation suite jo red team professionals aur bug hunters ke liye design kiya gaya hai. Ye toolkit advanced OSINT techniques use karta hai hidden vulnerabilities aur sensitive information discover karne ke liye.

### ✨ Key Features

- **🔍 Advanced Subdomain Discovery**: Certificate transparency, DNS bruteforcing, multiple APIs
- **☁️ Cloud Storage Hunting**: AWS S3, Google Cloud, Azure, DigitalOcean bucket enumeration
- **🔐 GitHub Secrets Discovery**: Automated dorking for API keys, credentials, sensitive data
- **🌐 Admin Panel Detection**: 500+ admin paths, CMS detection, login page discovery
- **🎯 Google Dorking**: 1000+ elite dorks for sensitive file exposure
- **📡 Shodan/Censys Integration**: IoT devices, exposed services, infrastructure mapping
- **🤖 Full Automation**: Master script combines all tools with HTML reporting

## 🚀 Quick Installation

```bash
# Clone or download the toolkit
wget https://raw.githubusercontent.com/your-repo/install.sh
chmod +x install.sh
./install.sh

# Or manual installation
pip3 install requests urllib3 pathlib argparse concurrent.futures
sudo apt install nmap curl wget git jq  # Linux
brew install nmap curl wget git jq     # macOS
```

## ⚡ Quick Start

### Master Automation (Recommended)
```bash
# Complete OSINT reconnaissance
python3 elite_osint_master.py example.com

# With GitHub token for better results
python3 elite_osint_master.py example.com -g ghp_xxxxxxxxxxxxxxxxxxxx

# Custom output directory
python3 elite_osint_master.py example.com -o my_results
```

### Individual Tools
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

## 📁 Toolkit Components

### 🔧 Core Scripts

| Script | Purpose | Features |
|--------|---------|----------|
| `elite_osint_master.py` | Master automation | Combines all tools, HTML reporting |
| `elite_recon_automation.py` | Subdomain discovery | crt.sh, APIs, live verification |
| `cloud_bucket_hunter.py` | Cloud storage hunting | AWS, GCP, Azure, DO enumeration |
| `github_secrets_hunter.py` | GitHub dorking | API keys, credentials, secrets |
| `admin_panel_hunter.py` | Admin panel discovery | 500+ paths, CMS detection |

### 📚 Resource Files

| File | Purpose | Content |
|------|---------|---------|
| `elite_google_dorks.txt` | Google dorking | 1000+ elite dorks |
| `elite_shodan_censys_queries.txt` | IoT/Infrastructure | Shodan, Censys, FOFA queries |
| `Elite_OSINT_Bug_Hunting_Workflow.md` | Complete methodology | Red team techniques |
| `USAGE_GUIDE.md` | Detailed documentation | Usage examples, tips |
| `install.sh` | Automated installer | Dependencies, setup |

## 🎯 Usage Examples

### 1. Complete Reconnaissance
```bash
# Full OSINT with all modules
python3 elite_osint_master.py target.com -g YOUR_GITHUB_TOKEN

# Output:
# - target.com_subdomains.txt (discovered subdomains)
# - target.com_alive_subdomains.txt (live subdomains)
# - target.com_cloud_buckets.json (exposed buckets)
# - target.com_github_secrets.json (found secrets)
# - admin_panels_TIMESTAMP.txt (admin panels)
# - OSINT_Report_target.com.html (comprehensive report)
```

### 2. Stealth Reconnaissance
```bash
# Only passive techniques
python3 elite_osint_master.py target.com --skip port_scanning admin_panel_hunting
```

### 3. Targeted Cloud Hunting
```bash
# Focus on cloud storage
python3 cloud_bucket_hunter.py target.com

# Results:
# - AWS S3 buckets with public access
# - Google Cloud Storage containers
# - Azure Blob storage exposure
# - DigitalOcean Spaces discovery
```

### 4. GitHub Intelligence
```bash
# Hunt for secrets in repositories
python3 github_secrets_hunter.py target.com ghp_token

# Discovers:
# - API keys and tokens
# - Database credentials
# - AWS/GCP/Azure keys
# - Private keys and certificates
```

## 🔍 Advanced Techniques

### Google Dorking Examples
```bash
# Sensitive files
site:target.com filetype:env
site:target.com "index of" backup
site:target.com inurl:admin login

# Database errors
site:target.com "mysql error"
site:target.com "access denied for user"

# Configuration files
site:target.com filetype:config
site:target.com ".git" OR ".env"
```

### Shodan Queries
```bash
# Infrastructure discovery
hostname:"target.com"
ssl:"target.com"
org:"Target Company"

# Exposed services
"Apache" hostname:"target.com"
port:22 hostname:"target.com"
"admin" "login" hostname:"target.com"
```

## 📊 Output & Reporting

### Generated Files
- **JSON Reports**: Structured data for further processing
- **Text Files**: Human-readable results
- **HTML Report**: Comprehensive visual report
- **URL Lists**: Easy access to discovered resources

### Report Sections
1. **Executive Summary**: High-level statistics
2. **Subdomain Analysis**: Discovery and verification results
3. **Cloud Storage**: Exposed buckets and permissions
4. **GitHub Intelligence**: Secrets and sensitive data
5. **Admin Panels**: Login pages and management interfaces
6. **Next Steps**: Manual verification recommendations

## 🛡️ Security & Ethics

### ✅ Authorized Testing Only
- Only test domains you own or have explicit permission
- Get written authorization before testing third-party systems
- Follow responsible disclosure practices
- Respect scope limitations and boundaries

### ✅ Rate Limiting & Respect
- Don't overwhelm target systems
- Respect robots.txt and terms of service
- Use reasonable delays between requests
- Monitor your impact on systems

### ❌ Prohibited Activities
- Testing without authorization
- Accessing unauthorized systems
- Causing disruption or damage
- Violating terms of service

## 🔧 Configuration & Customization

### API Keys (Optional but Recommended)
```bash
# GitHub Personal Access Token
# https://github.com/settings/tokens

# VirusTotal API Key
# https://www.virustotal.com/gui/join-us

# Shodan API Key
# https://account.shodan.io/register
```

### Custom Wordlists
```bash
# Add custom subdomain wordlists
~/elite_osint_toolkit/wordlists/custom_subdomains.txt

# Add custom admin paths
~/elite_osint_toolkit/wordlists/custom_admin_paths.txt
```

## 🚀 Advanced Usage

### Automation & Monitoring
```bash
# Cron job for continuous monitoring
0 2 * * * /usr/bin/python3 /path/to/elite_osint_master.py target.com

# Integration with other tools
cat target.com_subdomains.txt | httpx -silent | nuclei
```

### Custom Workflows
```bash
# Create custom reconnaissance workflows
python3 elite_osint_master.py target.com --skip github_secrets_hunting
python3 custom_verification.py target.com_results/
```

## 📈 Performance & Optimization

### Speed Optimization
- Use API keys for higher rate limits
- Adjust concurrent thread counts
- Implement custom delays for stealth
- Use VPN rotation for large-scale scans

### Resource Management
- Monitor memory usage for large target lists
- Implement result caching for repeated scans
- Use disk-based storage for large datasets
- Optimize network timeouts

## 🤝 Contributing

### How to Contribute
1. **Report Bugs**: Submit detailed bug reports
2. **Feature Requests**: Suggest new capabilities
3. **Code Contributions**: Submit pull requests
4. **Documentation**: Improve guides and examples
5. **Wordlists**: Share new dorks and patterns

### Development Setup
```bash
git clone https://github.com/your-repo/elite-osint-toolkit
cd elite-osint-toolkit
pip3 install -r requirements.txt
python3 -m pytest tests/
```

## 📚 Learning Resources

### OSINT Methodology
- [Elite_OSINT_Bug_Hunting_Workflow.md](Elite_OSINT_Bug_Hunting_Workflow.md)
- [USAGE_GUIDE.md](USAGE_GUIDE.md)
- Red team reconnaissance techniques
- Bug bounty hunting strategies

### External Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [Awesome OSINT](https://github.com/jivoi/awesome-osint)

## 🔄 Updates & Maintenance

### Staying Updated
```bash
# Update toolkit
cd ~/elite_osint_toolkit
./update.sh

# Manual updates
pip3 install --upgrade requests urllib3
git pull origin main
```

### Version History
- **v1.0**: Initial release with core functionality
- **v1.1**: Added cloud storage hunting
- **v1.2**: Enhanced GitHub secrets discovery
- **v1.3**: Master automation script
- **v1.4**: HTML reporting and UI improvements

## 🆘 Troubleshooting

### Common Issues

#### No Results Found
```bash
# Possible causes and solutions:
# - Strong security posture: Try different techniques
# - Rate limiting: Use API keys, VPN rotation
# - Network issues: Check connectivity
# - Target validation: Verify domain exists
```

#### Permission Errors
```bash
# Fix file permissions
chmod +x *.py
chmod +x install.sh

# Install missing dependencies
pip3 install -r requirements.txt
```

#### Rate Limiting
```bash
# Solutions:
# - Use API keys for higher limits
# - Implement delays between requests
# - Use VPN/proxy rotation
# - Run during off-peak hours
```

### Getting Help
1. Check [USAGE_GUIDE.md](USAGE_GUIDE.md) for detailed instructions
2. Review log files in output directory
3. Test with known working targets
4. Submit issues with detailed error messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This toolkit is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this toolkit.

## 🎯 Final Notes

### Best Practices
- Always get proper authorization
- Document your methodology
- Verify findings manually
- Follow responsible disclosure
- Keep tools updated
- Respect rate limits

### Success Tips
- Combine multiple techniques
- Use different search engines
- Cross-verify findings
- Think like an attacker
- Stay updated with new techniques
- Practice on authorized targets

---

**Happy Hunting! 🎯🔥**

*Elite OSINT Bug Hunting Toolkit - Empowering ethical hackers and security professionals worldwide.*

## 📞 Contact & Support

- **Issues**: Submit via GitHub Issues
- **Documentation**: Check USAGE_GUIDE.md
- **Updates**: Follow repository for latest releases
- **Community**: Join discussions and share techniques

Remember: **Use responsibly, hunt ethically, secure the world! 🌍🔒**