#!/usr/bin/env python3
"""
Elite Admin Panel Hunter
Automated Discovery of Admin Panels, Login Pages & Dashboards
Red Team OSINT Tool - Free Version
"""

import requests
import concurrent.futures
import time
import sys
import json
from urllib.parse import urljoin, urlparse
import re
from threading import Lock

class AdminPanelHunter:
    def __init__(self, target_list):
        self.targets = target_list if isinstance(target_list, list) else [target_list]
        self.found_panels = []
        self.lock = Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()
        
    def banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                🔐 ELITE ADMIN PANEL HUNTER 🔐                ║
║              Login Pages & Dashboard Discovery              ║
║                    Red Team OSINT Tool                      ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def get_admin_paths(self):
        """Get comprehensive list of admin panel paths"""
        return [
            # Generic Admin Paths
            'admin', 'administrator', 'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
            'admin.jsp', 'admin/', 'admin/index.php', 'admin/index.html', 'admin/login.php',
            'admin/login.html', 'admin/home.php', 'admin/controlpanel.php', 'admin/admin-login.php',
            'admin-login.php', 'admin_login.php', 'admin_login.html', 'admin/account.php',
            'admin/admin.php', 'admin/admin.html', 'admin_area/admin.php', 'admin_area/login.php',
            'admin_area/index.php', 'admin_area/', 'admin_area/admin.html', 'admin_area/login.html',
            
            # Control Panels
            'controlpanel', 'controlpanel.php', 'controlpanel.html', 'controlpanel/', 'cp.php',
            'cp.html', 'cp/', 'cpanel', 'cpanel.php', 'cpanel.html', 'cpanel/', 'panel.php',
            'panel.html', 'panel/', 'adminpanel', 'adminpanel.php', 'adminpanel.html',
            'adminpanel/', 'admin-panel', 'admin-panel.php', 'admin-panel.html', 'admin-panel/',
            
            # Login Pages
            'login', 'login.php', 'login.html', 'login.asp', 'login.aspx', 'login.jsp',
            'login/', 'login/index.php', 'login/index.html', 'signin', 'signin.php',
            'signin.html', 'signin/', 'sign-in', 'sign-in.php', 'sign-in.html', 'sign-in/',
            'log-in', 'log-in.php', 'log-in.html', 'log-in/', 'logon', 'logon.php',
            'logon.html', 'logon/', 'auth', 'auth.php', 'auth.html', 'auth/',
            
            # Dashboard
            'dashboard', 'dashboard.php', 'dashboard.html', 'dashboard/', 'dash', 'dash.php',
            'dash.html', 'dash/', 'home', 'home.php', 'home.html', 'home/', 'index.php',
            'main', 'main.php', 'main.html', 'main/', 'portal', 'portal.php', 'portal.html',
            
            # Management Interfaces
            'manage', 'manage.php', 'manage.html', 'manage/', 'management', 'management.php',
            'management.html', 'management/', 'manager', 'manager.php', 'manager.html',
            'manager/', 'moderator', 'moderator.php', 'moderator.html', 'moderator/',
            
            # Web-based Applications
            'phpmyadmin', 'phpMyAdmin', 'pma', 'mysql', 'mysql.php', 'mysql/', 'database',
            'database.php', 'database/', 'db', 'db.php', 'db/', 'webmail', 'mail',
            'mail.php', 'mail/', 'email', 'email.php', 'email/', 'roundcube', 'squirrelmail',
            
            # CMS Admin Areas
            'wp-admin', 'wp-admin/', 'wp-login.php', 'wordpress/wp-admin/', 'blog/wp-admin/',
            'joomla/administrator', 'administrator', 'administrator/', 'drupal/admin',
            'admin/drupal', 'magento/admin', 'admin/magento', 'prestashop/admin',
            'admin/prestashop', 'opencart/admin', 'admin/opencart',
            
            # Framework Admin
            'django-admin', 'django/admin', 'rails/admin', 'laravel/admin', 'admin/laravel',
            'symfony/admin', 'admin/symfony', 'codeigniter/admin', 'admin/codeigniter',
            
            # Server Admin Tools
            'webmin', 'webmin/', 'plesk', 'plesk/', 'directadmin', 'directadmin/',
            'ispconfig', 'ispconfig/', 'vesta', 'vesta/', 'froxlor', 'froxlor/',
            'kloxo', 'kloxo/', 'zpanel', 'zpanel/', 'sentora', 'sentora/',
            
            # Monitoring & Analytics
            'nagios', 'nagios/', 'zabbix', 'zabbix/', 'cacti', 'cacti/', 'munin',
            'munin/', 'awstats', 'awstats/', 'webalizer', 'webalizer/', 'piwik',
            'piwik/', 'matomo', 'matomo/', 'analytics', 'analytics/', 'stats',
            'stats/', 'statistics', 'statistics/',
            
            # Development Tools
            'jenkins', 'jenkins/', 'gitlab', 'gitlab/', 'gitea', 'gitea/', 'gogs',
            'gogs/', 'redmine', 'redmine/', 'trac', 'trac/', 'mantis', 'mantis/',
            'bugzilla', 'bugzilla/', 'jira', 'jira/', 'confluence', 'confluence/',
            
            # Security Tools
            'ossec', 'ossec/', 'snort', 'snort/', 'suricata', 'suricata/', 'wazuh',
            'wazuh/', 'elk', 'elk/', 'kibana', 'kibana/', 'grafana', 'grafana/',
            'splunk', 'splunk/', 'graylog', 'graylog/',
            
            # Network Tools
            'pfsense', 'pfsense/', 'opnsense', 'opnsense/', 'untangle', 'untangle/',
            'sophos', 'sophos/', 'fortinet', 'fortinet/', 'checkpoint', 'checkpoint/',
            'cisco', 'cisco/', 'juniper', 'juniper/', 'mikrotik', 'mikrotik/',
            
            # Backup & Storage
            'bacula', 'bacula/', 'amanda', 'amanda/', 'bareos', 'bareos/', 'duplicati',
            'duplicati/', 'nextcloud', 'nextcloud/', 'owncloud', 'owncloud/',
            'seafile', 'seafile/', 'syncthing', 'syncthing/',
            
            # Virtualization
            'vmware', 'vmware/', 'vcenter', 'vcenter/', 'esxi', 'esxi/', 'proxmox',
            'proxmox/', 'xen', 'xen/', 'kvm', 'kvm/', 'docker', 'docker/',
            'kubernetes', 'kubernetes/', 'rancher', 'rancher/', 'portainer', 'portainer/',
            
            # Common Variations
            'adm', 'adm.php', 'adm.html', 'adm/', 'root', 'root.php', 'root.html',
            'root/', 'super', 'super.php', 'super.html', 'super/', 'secret',
            'secret.php', 'secret.html', 'secret/', 'private', 'private.php',
            'private.html', 'private/', 'secure', 'secure.php', 'secure.html', 'secure/',
            
            # Language Specific
            'admin.do', 'admin.action', 'admin.cfm', 'admin.cgi', 'admin.pl',
            'admin.py', 'admin.rb', 'login.do', 'login.action', 'login.cfm',
            'login.cgi', 'login.pl', 'login.py', 'login.rb',
            
            # Mobile & API
            'mobile/admin', 'mobile/login', 'api/admin', 'api/login', 'api/auth',
            'rest/admin', 'rest/login', 'rest/auth', 'v1/admin', 'v1/login',
            'v1/auth', 'v2/admin', 'v2/login', 'v2/auth',
            
            # Subdirectories
            'site/admin', 'site/login', 'web/admin', 'web/login', 'www/admin',
            'www/login', 'public/admin', 'public/login', 'app/admin', 'app/login',
            'application/admin', 'application/login', 'system/admin', 'system/login',
            
            # Port-based (will be handled separately)
            # These are common admin ports: 8080, 8443, 9090, 9443, 10000, etc.
        ]
    
    def get_common_admin_ports(self):
        """Get common admin panel ports"""
        return [80, 443, 8080, 8443, 8000, 8888, 9090, 9443, 10000, 8081, 8082, 3000, 5000]
    
    def check_admin_panel(self, url):
        """Check if URL is an admin panel"""
        try:
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            
            # Check status code
            if response.status_code not in [200, 401, 403]:
                return None
            
            content = response.text.lower()
            title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else "No Title"
            
            # Admin panel indicators
            admin_indicators = [
                'admin', 'administrator', 'login', 'dashboard', 'control panel',
                'management', 'manager', 'moderator', 'signin', 'sign in',
                'log in', 'logon', 'authentication', 'auth', 'panel',
                'cpanel', 'plesk', 'webmin', 'phpmyadmin', 'mysql',
                'wordpress', 'joomla', 'drupal', 'magento', 'prestashop',
                'jenkins', 'gitlab', 'grafana', 'kibana', 'nagios',
                'zabbix', 'splunk', 'pfsense', 'vmware', 'proxmox'
            ]
            
            # Form indicators
            form_indicators = [
                'password', 'username', 'user', 'email', 'login',
                'signin', 'auth', 'credential'
            ]
            
            # Check for admin indicators
            admin_score = 0
            found_indicators = []
            
            for indicator in admin_indicators:
                if indicator in content or indicator in title.lower():
                    admin_score += 1
                    found_indicators.append(indicator)
            
            # Check for login forms
            has_login_form = False
            if any(form_ind in content for form_ind in form_indicators):
                if 'input' in content and 'password' in content:
                    has_login_form = True
                    admin_score += 2
            
            # Check for specific admin panel signatures
            signatures = {
                'phpMyAdmin': 'phpmyadmin',
                'WordPress': 'wp-login',
                'Joomla': 'joomla',
                'Drupal': 'drupal',
                'cPanel': 'cpanel',
                'Plesk': 'plesk',
                'Webmin': 'webmin',
                'Jenkins': 'jenkins',
                'GitLab': 'gitlab',
                'Grafana': 'grafana',
                'Kibana': 'kibana',
                'Nagios': 'nagios',
                'Zabbix': 'zabbix',
                'Splunk': 'splunk',
                'pfSense': 'pfsense',
                'VMware': 'vmware',
                'Proxmox': 'proxmox'
            }
            
            detected_platform = "Unknown"
            for platform, signature in signatures.items():
                if signature in content:
                    detected_platform = platform
                    admin_score += 3
                    break
            
            # Determine if this is likely an admin panel
            if admin_score >= 2 or has_login_form or response.status_code in [401, 403]:
                panel_info = {
                    'url': url,
                    'status_code': response.status_code,
                    'title': title,
                    'platform': detected_platform,
                    'has_login_form': has_login_form,
                    'indicators': found_indicators,
                    'admin_score': admin_score,
                    'content_length': len(response.text),
                    'server': response.headers.get('Server', 'Unknown'),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                with self.lock:
                    self.found_panels.append(panel_info)
                
                status_emoji = "🔒" if response.status_code in [401, 403] else "🎯"
                print(f"[{status_emoji}] FOUND: {url} - {title} ({response.status_code})")
                if detected_platform != "Unknown":
                    print(f"    Platform: {detected_platform}")
                
                return panel_info
        
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            pass
        
        return None
    
    def scan_target(self, target):
        """Scan a single target for admin panels"""
        print(f"[+] Scanning target: {target}")
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            targets_to_scan = [f'https://{target}', f'http://{target}']
        else:
            targets_to_scan = [target]
        
        admin_paths = self.get_admin_paths()
        
        # Scan each protocol variant
        for base_target in targets_to_scan:
            # Test base URL first
            self.check_admin_panel(base_target)
            
            # Test admin paths
            for path in admin_paths:
                url = urljoin(base_target, path)
                self.check_admin_panel(url)
            
            # Test common admin ports (only for domain targets)
            if not urlparse(base_target).port:
                domain = urlparse(base_target).netloc
                for port in self.get_common_admin_ports():
                    if port not in [80, 443]:  # Skip default ports
                        port_url = f"{urlparse(base_target).scheme}://{domain}:{port}"
                        self.check_admin_panel(port_url)
                        
                        # Test some common paths on non-standard ports
                        for path in ['admin', 'login', 'dashboard', 'manager']:
                            port_path_url = urljoin(port_url, path)
                            self.check_admin_panel(port_path_url)
    
    def hunt_admin_panels(self, max_workers=20):
        """Main admin panel hunting function"""
        self.banner()
        print(f"[+] Starting admin panel hunting")
        print(f"[+] Targets: {len(self.targets)}")
        print(f"[+] Admin paths to test: {len(self.get_admin_paths())}")
        print(f"[+] Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.scan_target, self.targets)
        
        print("="*60)
        print(f"[✓] Admin panel hunting completed!")
        print(f"[✓] Found {len(self.found_panels)} admin panels/login pages")
        
        if self.found_panels:
            print("\n🎯 DISCOVERED ADMIN PANELS:")
            for panel in self.found_panels:
                status_emoji = "🔒" if panel['status_code'] in [401, 403] else "🎯"
                print(f"  {status_emoji} {panel['url']}")
                print(f"    Title: {panel['title']}")
                print(f"    Status: {panel['status_code']}")
                if panel['platform'] != "Unknown":
                    print(f"    Platform: {panel['platform']}")
                if panel['has_login_form']:
                    print(f"    Has Login Form: Yes")
                print()
        
        self.save_results()
        return self.found_panels
    
    def save_results(self):
        """Save results to files"""
        if not self.found_panels:
            print("[!] No admin panels found to save")
            return
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Save detailed JSON results
        with open(f'admin_panels_{timestamp}.json', 'w') as f:
            json.dump({
                'targets': self.targets,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_found': len(self.found_panels),
                'panels': self.found_panels
            }, f, indent=2)
        
        # Save simple text report
        with open(f'admin_panels_{timestamp}.txt', 'w') as f:
            f.write(f"Admin Panel Discovery Report\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets: {', '.join(self.targets)}\n")
            f.write(f"Total Found: {len(self.found_panels)}\n")
            f.write("="*60 + "\n\n")
            
            for panel in self.found_panels:
                f.write(f"URL: {panel['url']}\n")
                f.write(f"Title: {panel['title']}\n")
                f.write(f"Status Code: {panel['status_code']}\n")
                f.write(f"Platform: {panel['platform']}\n")
                f.write(f"Has Login Form: {panel['has_login_form']}\n")
                f.write(f"Server: {panel['server']}\n")
                f.write(f"Admin Score: {panel['admin_score']}\n")
                f.write(f"Indicators: {', '.join(panel['indicators'])}\n")
                f.write("\n" + "-"*40 + "\n\n")
        
        # Save URLs only for easy access
        with open(f'admin_urls_{timestamp}.txt', 'w') as f:
            for panel in self.found_panels:
                f.write(f"{panel['url']}\n")
        
        print(f"[✓] Results saved to:")
        print(f"    • admin_panels_{timestamp}.json")
        print(f"    • admin_panels_{timestamp}.txt")
        print(f"    • admin_urls_{timestamp}.txt")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 admin_panel_hunter.py <target1> [target2] [target3] ...")
        print("       python3 admin_panel_hunter.py -f <targets_file>")
        print("\nExamples:")
        print("  python3 admin_panel_hunter.py example.com")
        print("  python3 admin_panel_hunter.py example.com test.com demo.org")
        print("  python3 admin_panel_hunter.py -f targets.txt")
        sys.exit(1)
    
    # Handle file input
    if sys.argv[1] == '-f' and len(sys.argv) > 2:
        try:
            with open(sys.argv[2], 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {sys.argv[2]}")
            sys.exit(1)
    else:
        targets = sys.argv[1:]
    
    hunter = AdminPanelHunter(targets)
    results = hunter.hunt_admin_panels()
    
    if results:
        print(f"\n🎯 SUCCESS: Found {len(results)} admin panels/login pages!")
        print("⚠️  Remember to test these findings responsibly and ethically!")
        print("💡 Check the generated files for detailed information.")
    else:
        print("\n❌ No admin panels found for the specified targets.")
        print("💡 Try different targets or check manually.")

if __name__ == "__main__":
    main()