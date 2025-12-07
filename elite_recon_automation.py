#!/usr/bin/env python3
"""
Elite OSINT Bug Hunting Automation Script
Red Team Style - Free Tools Only
Author: Elite Bug Hunter
"""

import requests
import json
import subprocess
import time
import sys
import os
from urllib.parse import urlparse
import concurrent.futures
from threading import Lock

class EliteRecon:
    def __init__(self, target):
        self.target = target
        self.subdomains = set()
        self.results = {}
        self.lock = Lock()
        
    def banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    🔥 ELITE OSINT RECON 🔥                   ║
║                   Red Team Bug Hunting Tool                  ║
║                      Free & Open Source                      ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
    def crt_sh_enum(self):
        """Certificate Transparency Subdomain Discovery"""
        print(f"[+] Certificate Transparency enumeration for {self.target}")
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        domains = name_value.split('\n')
                        for domain in domains:
                            domain = domain.strip().replace('*.', '')
                            if domain and self.target in domain:
                                self.subdomains.add(domain)
                print(f"[✓] Found {len(self.subdomains)} subdomains from crt.sh")
        except Exception as e:
            print(f"[!] Error in crt.sh enumeration: {e}")
    
    def virustotal_enum(self, api_key=None):
        """VirusTotal Subdomain Discovery"""
        if not api_key:
            print("[!] VirusTotal API key not provided, skipping...")
            return
            
        print(f"[+] VirusTotal enumeration for {self.target}")
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': self.target}
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        self.subdomains.add(subdomain)
                print(f"[✓] VirusTotal enumeration completed")
        except Exception as e:
            print(f"[!] Error in VirusTotal enumeration: {e}")
    
    def hackertarget_enum(self):
        """HackerTarget Free API"""
        print(f"[+] HackerTarget enumeration for {self.target}")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and self.target in subdomain:
                            self.subdomains.add(subdomain)
                print(f"[✓] HackerTarget enumeration completed")
        except Exception as e:
            print(f"[!] Error in HackerTarget enumeration: {e}")
    
    def threatcrowd_enum(self):
        """ThreatCrowd API"""
        print(f"[+] ThreatCrowd enumeration for {self.target}")
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        self.subdomains.add(subdomain)
                print(f"[✓] ThreatCrowd enumeration completed")
        except Exception as e:
            print(f"[!] Error in ThreatCrowd enumeration: {e}")
    
    def check_alive_subdomains(self):
        """Check which subdomains are alive"""
        print(f"[+] Checking alive subdomains...")
        alive_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=10, verify=False)
                    if response.status_code < 400:
                        with self.lock:
                            alive_subdomains.append({
                                'subdomain': subdomain,
                                'url': url,
                                'status_code': response.status_code,
                                'title': self.extract_title(response.text)
                            })
                        return
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, list(self.subdomains))
        
        self.results['alive_subdomains'] = alive_subdomains
        print(f"[✓] Found {len(alive_subdomains)} alive subdomains")
        return alive_subdomains
    
    def extract_title(self, html):
        """Extract title from HTML"""
        try:
            start = html.find('<title>') + 7
            end = html.find('</title>')
            if start > 6 and end > start:
                return html[start:end].strip()
        except:
            pass
        return "No Title"
    
    def google_dorking(self):
        """Advanced Google Dorking"""
        print(f"[+] Preparing Google Dorks for {self.target}")
        
        dorks = [
            f'site:{self.target} filetype:pdf | filetype:doc | filetype:xls',
            f'site:{self.target} filetype:sql | filetype:db | filetype:log',
            f'site:{self.target} "index of" | "directory listing"',
            f'site:{self.target} inurl:admin | inurl:login | inurl:dashboard',
            f'site:{self.target} "password" | "username" | "login"',
            f'site:{self.target} "mysql error" | "sql syntax" | "warning:"',
            f'site:{self.target} inurl:api | inurl:v1 | inurl:rest',
            f'site:{self.target} ".git" | ".env" | "config"',
            f'site:{self.target} inurl:dev | inurl:test | inurl:staging',
            f'site:{self.target} "phpinfo()" | "server-status"'
        ]
        
        self.results['google_dorks'] = dorks
        print(f"[✓] Generated {len(dorks)} Google dorks")
        
        # Save dorks to file
        with open(f'{self.target}_google_dorks.txt', 'w') as f:
            for dork in dorks:
                f.write(f"{dork}\n")
        
        return dorks
    
    def github_dorking(self):
        """GitHub Dorking Queries"""
        print(f"[+] Preparing GitHub Dorks for {self.target}")
        
        github_dorks = [
            f'"{self.target}" password',
            f'"{self.target}" api_key OR apikey OR api-key',
            f'"{self.target}" secret_key OR secretkey',
            f'"{self.target}" access_token OR accesstoken',
            f'"{self.target}" config OR configuration',
            f'"{self.target}" database OR db_password',
            f'"{self.target}" smtp OR email OR mail',
            f'"{self.target}" aws_access_key OR aws_secret',
            f'"{self.target}" private_key OR privatekey',
            f'"{self.target}" filename:.env',
            f'"{self.target}" filename:config.php',
            f'"{self.target}" filename:database.yml',
            f'"{self.target}" filename:settings.py'
        ]
        
        self.results['github_dorks'] = github_dorks
        print(f"[✓] Generated {len(github_dorks)} GitHub dorks")
        
        # Save GitHub dorks to file
        with open(f'{self.target}_github_dorks.txt', 'w') as f:
            for dork in github_dorks:
                f.write(f"{dork}\n")
        
        return github_dorks
    
    def shodan_queries(self):
        """Shodan Search Queries"""
        print(f"[+] Preparing Shodan queries for {self.target}")
        
        shodan_queries = [
            f'hostname:"{self.target}"',
            f'ssl:"{self.target}"',
            f'org:"{self.target}"',
            f'"Apache" "{self.target}"',
            f'"nginx" "{self.target}"',
            f'"IIS" "{self.target}"',
            f'port:22 "{self.target}"',
            f'port:3389 "{self.target}"',
            f'port:21 "{self.target}"',
            f'port:3306 "{self.target}"',
            f'port:5432 "{self.target}"',
            f'port:27017 "{self.target}"',
            f'port:6379 "{self.target}"',
            f'"admin" "login" "{self.target}"',
            f'"dashboard" "{self.target}"',
            f'"jenkins" "{self.target}"',
            f'"grafana" "{self.target}"'
        ]
        
        self.results['shodan_queries'] = shodan_queries
        print(f"[✓] Generated {len(shodan_queries)} Shodan queries")
        
        # Save Shodan queries to file
        with open(f'{self.target}_shodan_queries.txt', 'w') as f:
            for query in shodan_queries:
                f.write(f"{query}\n")
        
        return shodan_queries
    
    def cloud_storage_enum(self):
        """Cloud Storage Enumeration"""
        print(f"[+] Preparing cloud storage enumeration for {self.target}")
        
        # Common bucket naming patterns
        company_name = self.target.split('.')[0]
        bucket_patterns = [
            f"{company_name}",
            f"{company_name}-backup",
            f"{company_name}-backups",
            f"{company_name}-dev",
            f"{company_name}-development",
            f"{company_name}-prod",
            f"{company_name}-production",
            f"{company_name}-staging",
            f"{company_name}-test",
            f"{company_name}-testing",
            f"{company_name}-assets",
            f"{company_name}-static",
            f"{company_name}-files",
            f"{company_name}-data",
            f"{company_name}-logs",
            f"{company_name}-uploads",
            f"{company_name}-images",
            f"{company_name}-documents",
            f"{company_name}-reports"
        ]
        
        # AWS S3 URLs
        s3_urls = []
        for pattern in bucket_patterns:
            s3_urls.extend([
                f"https://{pattern}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{pattern}",
                f"https://{pattern}.s3-us-west-2.amazonaws.com",
                f"https://{pattern}.s3-eu-west-1.amazonaws.com"
            ])
        
        # Google Cloud Storage URLs
        gcs_urls = []
        for pattern in bucket_patterns:
            gcs_urls.append(f"https://storage.googleapis.com/{pattern}")
        
        # Azure Blob Storage URLs
        azure_urls = []
        for pattern in bucket_patterns:
            azure_urls.append(f"https://{pattern}.blob.core.windows.net")
        
        self.results['cloud_storage'] = {
            'aws_s3': s3_urls,
            'google_cloud': gcs_urls,
            'azure_blob': azure_urls
        }
        
        print(f"[✓] Generated {len(s3_urls + gcs_urls + azure_urls)} cloud storage URLs")
        
        # Save cloud storage URLs to file
        with open(f'{self.target}_cloud_storage.txt', 'w') as f:
            f.write("=== AWS S3 Buckets ===\n")
            for url in s3_urls:
                f.write(f"{url}\n")
            f.write("\n=== Google Cloud Storage ===\n")
            for url in gcs_urls:
                f.write(f"{url}\n")
            f.write("\n=== Azure Blob Storage ===\n")
            for url in azure_urls:
                f.write(f"{url}\n")
        
        return self.results['cloud_storage']
    
    def save_results(self):
        """Save all results to files"""
        print(f"[+] Saving results...")
        
        # Save subdomains
        with open(f'{self.target}_subdomains.txt', 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        # Save alive subdomains
        if 'alive_subdomains' in self.results:
            with open(f'{self.target}_alive_subdomains.txt', 'w') as f:
                for sub in self.results['alive_subdomains']:
                    f.write(f"{sub['url']} - {sub['status_code']} - {sub['title']}\n")
        
        # Save JSON results
        with open(f'{self.target}_results.json', 'w') as f:
            json.dump({
                'target': self.target,
                'total_subdomains': len(self.subdomains),
                'subdomains': list(self.subdomains),
                'results': self.results
            }, f, indent=2)
        
        print(f"[✓] Results saved to multiple files")
    
    def run_full_recon(self, vt_api_key=None):
        """Run complete reconnaissance"""
        self.banner()
        print(f"[+] Starting elite reconnaissance for: {self.target}")
        print(f"[+] Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Subdomain enumeration
        self.crt_sh_enum()
        self.hackertarget_enum()
        self.threatcrowd_enum()
        if vt_api_key:
            self.virustotal_enum(vt_api_key)
        
        # Check alive subdomains
        if self.subdomains:
            self.check_alive_subdomains()
        
        # Generate dorking queries
        self.google_dorking()
        self.github_dorking()
        self.shodan_queries()
        self.cloud_storage_enum()
        
        # Save results
        self.save_results()
        
        print("="*60)
        print(f"[✓] Reconnaissance completed!")
        print(f"[✓] Total subdomains found: {len(self.subdomains)}")
        if 'alive_subdomains' in self.results:
            print(f"[✓] Alive subdomains: {len(self.results['alive_subdomains'])}")
        print(f"[✓] Results saved with prefix: {self.target}_*")
        print("="*60)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 elite_recon_automation.py <target_domain> [virustotal_api_key]")
        print("Example: python3 elite_recon_automation.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    vt_api_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    recon = EliteRecon(target)
    recon.run_full_recon(vt_api_key)

if __name__ == "__main__":
    main()