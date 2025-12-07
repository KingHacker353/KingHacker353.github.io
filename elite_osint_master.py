#!/usr/bin/env python3
"""
Elite OSINT Master - Complete Bug Hunting Automation
Combines all OSINT tools into one powerful script
Red Team Style - Free & Open Source
"""

import os
import sys
import time
import json
import argparse
import subprocess
from datetime import datetime
import concurrent.futures
from pathlib import Path

class EliteOSINTMaster:
    def __init__(self, target, output_dir=None):
        self.target = target
        self.company_name = target.split('.')[0]
        self.output_dir = output_dir or f"osint_results_{self.target}_{int(time.time())}"
        self.results = {}
        
        # Create output directory
        Path(self.output_dir).mkdir(exist_ok=True)
        
    def banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                🔥 ELITE OSINT MASTER SUITE 🔥                ║
║              Complete Bug Hunting Automation                ║
║                   Red Team OSINT Tool                       ║
║                    Free & Open Source                       ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
    def log(self, message, level="INFO"):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
        # Also save to log file
        with open(f"{self.output_dir}/osint_master.log", "a") as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    
    def run_subdomain_enumeration(self):
        """Run subdomain enumeration"""
        self.log("Starting subdomain enumeration...")
        
        try:
            # Run our elite recon automation
            cmd = f"python3 elite_recon_automation.py {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                self.log("Subdomain enumeration completed successfully")
                
                # Move results to output directory
                for file_pattern in [f"{self.target}_*.txt", f"{self.target}_*.json"]:
                    subprocess.run(f"mv {file_pattern} {self.output_dir}/ 2>/dev/null", shell=True)
                
                self.results['subdomain_enumeration'] = {
                    'status': 'completed',
                    'output': result.stdout
                }
            else:
                self.log(f"Subdomain enumeration failed: {result.stderr}", "ERROR")
                self.results['subdomain_enumeration'] = {
                    'status': 'failed',
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            self.log("Subdomain enumeration timed out", "WARNING")
        except Exception as e:
            self.log(f"Subdomain enumeration error: {e}", "ERROR")
    
    def run_cloud_bucket_hunting(self):
        """Run cloud bucket hunting"""
        self.log("Starting cloud bucket hunting...")
        
        try:
            cmd = f"python3 cloud_bucket_hunter.py {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                self.log("Cloud bucket hunting completed successfully")
                
                # Move results to output directory
                for file_pattern in [f"{self.target}_cloud_*.txt", f"{self.target}_cloud_*.json"]:
                    subprocess.run(f"mv {file_pattern} {self.output_dir}/ 2>/dev/null", shell=True)
                
                self.results['cloud_bucket_hunting'] = {
                    'status': 'completed',
                    'output': result.stdout
                }
            else:
                self.log(f"Cloud bucket hunting failed: {result.stderr}", "ERROR")
                self.results['cloud_bucket_hunting'] = {
                    'status': 'failed',
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            self.log("Cloud bucket hunting timed out", "WARNING")
        except Exception as e:
            self.log(f"Cloud bucket hunting error: {e}", "ERROR")
    
    def run_github_secrets_hunting(self, github_token=None):
        """Run GitHub secrets hunting"""
        self.log("Starting GitHub secrets hunting...")
        
        try:
            cmd = f"python3 github_secrets_hunter.py {self.target}"
            if github_token:
                cmd += f" {github_token}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                self.log("GitHub secrets hunting completed successfully")
                
                # Move results to output directory
                for file_pattern in [f"{self.target}_github_*.txt", f"{self.target}_github_*.json"]:
                    subprocess.run(f"mv {file_pattern} {self.output_dir}/ 2>/dev/null", shell=True)
                
                self.results['github_secrets_hunting'] = {
                    'status': 'completed',
                    'output': result.stdout
                }
            else:
                self.log(f"GitHub secrets hunting failed: {result.stderr}", "ERROR")
                self.results['github_secrets_hunting'] = {
                    'status': 'failed',
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            self.log("GitHub secrets hunting timed out", "WARNING")
        except Exception as e:
            self.log(f"GitHub secrets hunting error: {e}", "ERROR")
    
    def run_admin_panel_hunting(self):
        """Run admin panel hunting"""
        self.log("Starting admin panel hunting...")
        
        try:
            # First get subdomains if available
            subdomains_file = f"{self.output_dir}/{self.target}_subdomains.txt"
            targets = [self.target]
            
            if os.path.exists(subdomains_file):
                with open(subdomains_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    targets.extend(subdomains[:50])  # Limit to 50 subdomains
            
            # Create temporary targets file
            temp_targets_file = f"{self.output_dir}/temp_targets.txt"
            with open(temp_targets_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            
            cmd = f"python3 admin_panel_hunter.py -f {temp_targets_file}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                self.log("Admin panel hunting completed successfully")
                
                # Move results to output directory
                subprocess.run(f"mv admin_*.txt admin_*.json {self.output_dir}/ 2>/dev/null", shell=True)
                
                self.results['admin_panel_hunting'] = {
                    'status': 'completed',
                    'output': result.stdout
                }
            else:
                self.log(f"Admin panel hunting failed: {result.stderr}", "ERROR")
                self.results['admin_panel_hunting'] = {
                    'status': 'failed',
                    'error': result.stderr
                }
            
            # Clean up temp file
            if os.path.exists(temp_targets_file):
                os.remove(temp_targets_file)
                
        except subprocess.TimeoutExpired:
            self.log("Admin panel hunting timed out", "WARNING")
        except Exception as e:
            self.log(f"Admin panel hunting error: {e}", "ERROR")
    
    def generate_dork_files(self):
        """Generate Google dorks and search queries"""
        self.log("Generating Google dorks and search queries...")
        
        try:
            # Copy dork files to output directory
            dork_files = [
                'elite_google_dorks.txt',
                'elite_shodan_censys_queries.txt'
            ]
            
            for dork_file in dork_files:
                if os.path.exists(dork_file):
                    # Read and customize for target
                    with open(dork_file, 'r') as f:
                        content = f.read()
                    
                    # Replace target.com with actual target
                    customized_content = content.replace('target.com', self.target)
                    customized_content = customized_content.replace('Target Company', self.company_name.title())
                    
                    # Save customized version
                    output_file = f"{self.output_dir}/{self.target}_{dork_file}"
                    with open(output_file, 'w') as f:
                        f.write(customized_content)
                    
                    self.log(f"Generated customized {dork_file}")
            
            self.results['dork_generation'] = {
                'status': 'completed',
                'files_generated': len(dork_files)
            }
            
        except Exception as e:
            self.log(f"Dork generation error: {e}", "ERROR")
    
    def run_port_scanning(self):
        """Run basic port scanning"""
        self.log("Starting port scanning...")
        
        try:
            # Get alive subdomains if available
            alive_subdomains_file = f"{self.output_dir}/{self.target}_alive_subdomains.txt"
            targets = [self.target]
            
            if os.path.exists(alive_subdomains_file):
                with open(alive_subdomains_file, 'r') as f:
                    for line in f:
                        if 'https://' in line or 'http://' in line:
                            url = line.split(' - ')[0].strip()
                            domain = url.replace('https://', '').replace('http://', '').split('/')[0]
                            targets.append(domain)
            
            # Remove duplicates and limit
            targets = list(set(targets))[:20]  # Limit to 20 targets
            
            # Run nmap scan
            nmap_results = {}
            for target in targets:
                self.log(f"Scanning {target}...")
                cmd = f"nmap -sS -T4 -p 21,22,23,25,53,80,110,143,443,993,995,8080,8443,3389,5432,3306,1433,27017,6379 {target}"
                
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        nmap_results[target] = result.stdout
                except subprocess.TimeoutExpired:
                    self.log(f"Nmap scan for {target} timed out", "WARNING")
                except Exception as e:
                    self.log(f"Nmap scan error for {target}: {e}", "ERROR")
            
            # Save results
            if nmap_results:
                with open(f"{self.output_dir}/{self.target}_nmap_results.txt", 'w') as f:
                    for target, result in nmap_results.items():
                        f.write(f"=== NMAP SCAN RESULTS FOR {target} ===\n")
                        f.write(result)
                        f.write("\n" + "="*50 + "\n\n")
                
                self.results['port_scanning'] = {
                    'status': 'completed',
                    'targets_scanned': len(nmap_results)
                }
                self.log("Port scanning completed successfully")
            else:
                self.results['port_scanning'] = {
                    'status': 'failed',
                    'error': 'No successful scans'
                }
                
        except Exception as e:
            self.log(f"Port scanning error: {e}", "ERROR")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive HTML report"""
        self.log("Generating comprehensive report...")
        
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elite OSINT Report - {self.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }}
        .section {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .status-completed {{ color: #28a745; font-weight: bold; }}
        .status-failed {{ color: #dc3545; font-weight: bold; }}
        .file-list {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .file-list ul {{ margin: 0; padding-left: 20px; }}
        .summary-stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 Elite OSINT Report</h1>
            <h2>Target: {self.target}</h2>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-stats">
                <div class="stat-box">
                    <div class="stat-number">{len([r for r in self.results.values() if r.get('status') == 'completed'])}</div>
                    <div>Completed Scans</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len([f for f in os.listdir(self.output_dir) if f.endswith(('.txt', '.json'))])}</div>
                    <div>Files Generated</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">{len(self.results)}</div>
                    <div>Total Modules</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Scan Results</h2>
            """
            
            for module, result in self.results.items():
                status_class = f"status-{result.get('status', 'unknown')}"
                html_content += f"""
                <h3>{module.replace('_', ' ').title()}</h3>
                <p>Status: <span class="{status_class}">{result.get('status', 'Unknown').upper()}</span></p>
                """
                
                if result.get('error'):
                    html_content += f"<p><strong>Error:</strong> {result['error']}</p>"
            
            html_content += """
        </div>
        
        <div class="section">
            <h2>📁 Generated Files</h2>
            <div class="file-list">
                <ul>
            """
            
            # List all generated files
            for file in sorted(os.listdir(self.output_dir)):
                if file.endswith(('.txt', '.json')):
                    html_content += f"<li>{file}</li>"
            
            html_content += f"""
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Next Steps</h2>
            <ul>
                <li>Review all generated files for sensitive information</li>
                <li>Manually verify discovered admin panels and login pages</li>
                <li>Test cloud storage buckets for public access</li>
                <li>Analyze GitHub secrets for valid credentials</li>
                <li>Use Google dorks for manual verification</li>
                <li>Perform deeper reconnaissance on discovered subdomains</li>
                <li>Follow responsible disclosure practices</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>🔥 Elite OSINT Master Suite - Red Team OSINT Tool</p>
            <p>Generated for: {self.target} | Company: {self.company_name.title()}</p>
            <p><strong>⚠️ Use responsibly and only on authorized targets!</strong></p>
        </div>
    </div>
</body>
</html>
            """
            
            # Save HTML report
            with open(f"{self.output_dir}/OSINT_Report_{self.target}.html", 'w') as f:
                f.write(html_content)
            
            self.log("Comprehensive HTML report generated successfully")
            
        except Exception as e:
            self.log(f"Report generation error: {e}", "ERROR")
    
    def run_full_osint(self, github_token=None, skip_modules=None):
        """Run complete OSINT reconnaissance"""
        skip_modules = skip_modules or []
        
        self.banner()
        self.log(f"Starting Elite OSINT reconnaissance for: {self.target}")
        self.log(f"Output directory: {self.output_dir}")
        self.log("="*60)
        
        # Module execution order
        modules = [
            ('subdomain_enumeration', self.run_subdomain_enumeration),
            ('cloud_bucket_hunting', self.run_cloud_bucket_hunting),
            ('github_secrets_hunting', lambda: self.run_github_secrets_hunting(github_token)),
            ('admin_panel_hunting', self.run_admin_panel_hunting),
            ('dork_generation', self.generate_dork_files),
            ('port_scanning', self.run_port_scanning)
        ]
        
        # Execute modules
        for module_name, module_func in modules:
            if module_name not in skip_modules:
                self.log(f"Executing module: {module_name}")
                try:
                    module_func()
                except Exception as e:
                    self.log(f"Module {module_name} failed: {e}", "ERROR")
                    self.results[module_name] = {'status': 'failed', 'error': str(e)}
                
                self.log(f"Module {module_name} completed")
                self.log("-" * 40)
        
        # Generate final report
        self.generate_comprehensive_report()
        
        self.log("="*60)
        self.log("🎯 Elite OSINT reconnaissance completed!")
        self.log(f"📁 All results saved in: {self.output_dir}")
        self.log(f"📊 Open {self.output_dir}/OSINT_Report_{self.target}.html for detailed report")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Elite OSINT Master - Complete Bug Hunting Automation')
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('-g', '--github-token', help='GitHub API token for better rate limits')
    parser.add_argument('--skip', nargs='+', help='Skip specific modules', 
                       choices=['subdomain_enumeration', 'cloud_bucket_hunting', 'github_secrets_hunting', 
                               'admin_panel_hunting', 'dork_generation', 'port_scanning'])
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target or '.' not in args.target:
        print("[!] Please provide a valid domain name (e.g., example.com)")
        sys.exit(1)
    
    # Initialize and run
    osint_master = EliteOSINTMaster(args.target, args.output)
    results = osint_master.run_full_osint(args.github_token, args.skip)
    
    # Final summary
    completed = len([r for r in results.values() if r.get('status') == 'completed'])
    failed = len([r for r in results.values() if r.get('status') == 'failed'])
    
    print(f"\n🎯 FINAL SUMMARY:")
    print(f"   ✅ Completed modules: {completed}")
    print(f"   ❌ Failed modules: {failed}")
    print(f"   📁 Results directory: {osint_master.output_dir}")
    print(f"   📊 HTML Report: {osint_master.output_dir}/OSINT_Report_{args.target}.html")
    print(f"\n⚠️  Remember to use these findings responsibly and ethically!")

if __name__ == "__main__":
    main()