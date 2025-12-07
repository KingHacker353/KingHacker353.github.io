#!/usr/bin/env python3
"""
Elite GitHub Secrets Hunter
Automated GitHub Dorking for Sensitive Data Discovery
Red Team OSINT Tool - Free Version
"""

import requests
import time
import sys
import json
import re
from urllib.parse import quote
import concurrent.futures
from threading import Lock

class GitHubSecretsHunter:
    def __init__(self, target, github_token=None):
        self.target = target
        self.company_name = target.split('.')[0]
        self.github_token = github_token
        self.found_secrets = []
        self.lock = Lock()
        self.session = requests.Session()
        
        # Set up headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        if github_token:
            headers['Authorization'] = f'token {github_token}'
        
        self.session.headers.update(headers)
        
        # Rate limiting
        self.request_count = 0
        self.last_request_time = 0
        
    def banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                🔍 ELITE GITHUB SECRETS HUNTER 🔍             ║
║                   Automated Dorking Tool                    ║
║                    Red Team OSINT                           ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def rate_limit_handler(self):
        """Handle GitHub API rate limiting"""
        self.request_count += 1
        current_time = time.time()
        
        # If no token, be more conservative
        if not self.github_token:
            if self.request_count % 10 == 0:  # Every 10 requests
                time.sleep(12)  # Wait 12 seconds
        else:
            if self.request_count % 30 == 0:  # Every 30 requests
                time.sleep(2)  # Wait 2 seconds
        
        self.last_request_time = current_time
    
    def search_github(self, query, search_type='code'):
        """Search GitHub with rate limiting"""
        self.rate_limit_handler()
        
        try:
            if search_type == 'code':
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=100"
            else:
                url = f"https://api.github.com/search/repositories?q={quote(query)}&per_page=100"
            
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                print(f"[!] Rate limited. Waiting 60 seconds...")
                time.sleep(60)
                return self.search_github(query, search_type)  # Retry
            elif response.status_code == 422:
                print(f"[!] Query too complex: {query}")
                return None
            else:
                print(f"[!] Error {response.status_code} for query: {query}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Request error: {e}")
            return None
    
    def generate_search_queries(self):
        """Generate GitHub search queries"""
        print(f"[+] Generating GitHub search queries for: {self.target}")
        
        # Base queries with domain
        base_queries = [
            f'"{self.target}"',
            f'"{self.company_name}"',
            f'@{self.target}',
            f'{self.target.replace(".", " ")}'
        ]
        
        # Sensitive keywords
        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'api_key', 'apikey', 'api-key', 'access_token', 'accesstoken',
            'secret_key', 'secretkey', 'private_key', 'privatekey',
            'db_password', 'database_password', 'mysql_password',
            'postgres_password', 'mongodb_password', 'redis_password',
            'smtp_password', 'email_password', 'mail_password',
            'ftp_password', 'ssh_password', 'admin_password',
            'root_password', 'user_password', 'login_password',
            'aws_access_key_id', 'aws_secret_access_key',
            'aws_access_key', 'aws_secret_key', 'amazon_secret_access_key',
            'google_api_key', 'google_secret', 'gcp_key',
            'azure_key', 'azure_secret', 'microsoft_key',
            'github_token', 'gitlab_token', 'bitbucket_token',
            'slack_token', 'discord_token', 'telegram_token',
            'stripe_key', 'paypal_key', 'payment_key',
            'jwt_secret', 'session_secret', 'encryption_key',
            'certificate', 'cert', 'pem', 'p12', 'pfx',
            'connection_string', 'connectionstring', 'database_url',
            'redis_url', 'mongodb_url', 'mysql_url', 'postgres_url'
        ]
        
        # File extensions
        file_extensions = [
            '.env', '.config', '.conf', '.cfg', '.ini', '.yaml', '.yml',
            '.json', '.xml', '.properties', '.settings', '.plist',
            '.key', '.pem', '.p12', '.pfx', '.crt', '.cer'
        ]
        
        # Generate combined queries
        queries = []
        
        # Basic domain queries
        for base in base_queries:
            queries.append(base)
        
        # Domain + sensitive keywords
        for base in base_queries:
            for keyword in sensitive_keywords[:20]:  # Limit to avoid too many queries
                queries.append(f'{base} {keyword}')
        
        # Domain + file extensions
        for base in base_queries:
            for ext in file_extensions:
                queries.append(f'{base} filename:{ext}')
        
        # Specific file searches
        specific_files = [
            '.env', 'config.php', 'database.yml', 'settings.py',
            'config.json', 'secrets.json', 'credentials.json',
            'docker-compose.yml', 'Dockerfile', '.gitignore',
            'package.json', 'composer.json', 'requirements.txt'
        ]
        
        for base in base_queries:
            for filename in specific_files:
                queries.append(f'{base} filename:{filename}')
        
        # Language-specific searches
        languages = ['php', 'python', 'javascript', 'java', 'go', 'ruby']
        for base in base_queries:
            for lang in languages:
                queries.append(f'{base} language:{lang}')
        
        print(f"[✓] Generated {len(queries)} search queries")
        return queries[:100]  # Limit to 100 queries to avoid rate limiting
    
    def analyze_code_result(self, item, query):
        """Analyze code search result for sensitive data"""
        try:
            repo_name = item.get('repository', {}).get('full_name', 'Unknown')
            file_path = item.get('path', 'Unknown')
            html_url = item.get('html_url', '')
            
            # Get file content if available
            download_url = item.get('download_url')
            content = ""
            
            if download_url:
                try:
                    content_response = self.session.get(download_url, timeout=10)
                    if content_response.status_code == 200:
                        content = content_response.text[:2000]  # First 2000 chars
                except:
                    pass
            
            # Analyze for sensitive patterns
            sensitive_patterns = {
                'API Keys': [
                    r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})',
                    r'apikey["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})',
                    r'api[_-]?secret["\s]*[:=]["\s]*([a-zA-Z0-9_-]{20,})'
                ],
                'AWS Keys': [
                    r'AKIA[0-9A-Z]{16}',
                    r'aws[_-]?access[_-]?key["\s]*[:=]["\s]*([A-Z0-9]{20})',
                    r'aws[_-]?secret[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9/+=]{40})'
                ],
                'Database Credentials': [
                    r'db[_-]?password["\s]*[:=]["\s]*["\']([^"\']{6,})["\']',
                    r'database[_-]?password["\s]*[:=]["\s]*["\']([^"\']{6,})["\']',
                    r'mysql[_-]?password["\s]*[:=]["\s]*["\']([^"\']{6,})["\']'
                ],
                'Generic Passwords': [
                    r'password["\s]*[:=]["\s]*["\']([^"\']{6,})["\']',
                    r'passwd["\s]*[:=]["\s]*["\']([^"\']{6,})["\']',
                    r'pwd["\s]*[:=]["\s]*["\']([^"\']{6,})["\']'
                ],
                'Tokens': [
                    r'token["\s]*[:=]["\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
                    r'access[_-]?token["\s]*[:=]["\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
                    r'bearer["\s]*[:=]["\s]*["\']([a-zA-Z0-9_-]{20,})["\']'
                ],
                'Private Keys': [
                    r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                    r'private[_-]?key["\s]*[:=]["\s]*["\']([^"\']{50,})["\']'
                ]
            }
            
            findings = []
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0] if match[0] else match[1]
                            findings.append({
                                'category': category,
                                'pattern': pattern,
                                'match': match[:50] + '...' if len(match) > 50 else match
                            })
            
            if findings or any(keyword in content.lower() for keyword in ['password', 'secret', 'key', 'token']):
                secret_info = {
                    'query': query,
                    'repository': repo_name,
                    'file_path': file_path,
                    'url': html_url,
                    'findings': findings,
                    'content_preview': content[:500] + '...' if len(content) > 500 else content,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                with self.lock:
                    self.found_secrets.append(secret_info)
                
                print(f"[🎯] FOUND: {repo_name}/{file_path}")
                if findings:
                    for finding in findings:
                        print(f"    • {finding['category']}: {finding['match']}")
                
                return secret_info
        
        except Exception as e:
            print(f"[!] Error analyzing result: {e}")
        
        return None
    
    def search_secrets(self, query):
        """Search for secrets using a specific query"""
        print(f"[+] Searching: {query}")
        
        results = self.search_github(query, 'code')
        if not results or 'items' not in results:
            return
        
        items = results['items']
        print(f"    Found {len(items)} results")
        
        for item in items:
            self.analyze_code_result(item, query)
    
    def hunt_secrets(self, max_workers=5):
        """Main secrets hunting function"""
        self.banner()
        print(f"[+] Starting GitHub secrets hunting for: {self.target}")
        print(f"[+] Company name: {self.company_name}")
        if self.github_token:
            print("[+] Using GitHub token for higher rate limits")
        else:
            print("[!] No GitHub token provided - limited to 60 requests/hour")
        print(f"[+] Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        queries = self.generate_search_queries()
        
        print(f"[+] Executing {len(queries)} search queries...")
        print(f"[+] Using {max_workers} concurrent workers")
        print("="*60)
        
        # Use ThreadPoolExecutor with limited workers to respect rate limits
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.search_secrets, queries)
        
        print("="*60)
        print(f"[✓] GitHub secrets hunting completed!")
        print(f"[✓] Found {len(self.found_secrets)} potential secrets")
        
        if self.found_secrets:
            print("\n🎯 DISCOVERED SECRETS:")
            for secret in self.found_secrets[:10]:  # Show first 10
                print(f"  • {secret['repository']}/{secret['file_path']}")
                if secret['findings']:
                    for finding in secret['findings'][:3]:  # Show first 3 findings
                        print(f"    - {finding['category']}: {finding['match']}")
                print()
        
        self.save_results()
        return self.found_secrets
    
    def save_results(self):
        """Save results to files"""
        if not self.found_secrets:
            print("[!] No secrets found to save")
            return
        
        # Save detailed JSON results
        with open(f'{self.target}_github_secrets.json', 'w') as f:
            json.dump({
                'target': self.target,
                'company_name': self.company_name,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_found': len(self.found_secrets),
                'secrets': self.found_secrets
            }, f, indent=2)
        
        # Save simple text report
        with open(f'{self.target}_github_secrets.txt', 'w') as f:
            f.write(f"GitHub Secrets Discovery Report for {self.target}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Found: {len(self.found_secrets)}\n")
            f.write("="*60 + "\n\n")
            
            for secret in self.found_secrets:
                f.write(f"Repository: {secret['repository']}\n")
                f.write(f"File: {secret['file_path']}\n")
                f.write(f"URL: {secret['url']}\n")
                f.write(f"Query: {secret['query']}\n")
                
                if secret['findings']:
                    f.write("Findings:\n")
                    for finding in secret['findings']:
                        f.write(f"  • {finding['category']}: {finding['match']}\n")
                
                f.write(f"Content Preview:\n{secret['content_preview']}\n")
                f.write("\n" + "-"*40 + "\n\n")
        
        # Save URLs only for easy access
        with open(f'{self.target}_github_urls.txt', 'w') as f:
            for secret in self.found_secrets:
                f.write(f"{secret['url']}\n")
        
        print(f"[✓] Results saved to:")
        print(f"    • {self.target}_github_secrets.json")
        print(f"    • {self.target}_github_secrets.txt")
        print(f"    • {self.target}_github_urls.txt")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 github_secrets_hunter.py <target_domain> [github_token]")
        print("Example: python3 github_secrets_hunter.py example.com")
        print("Example: python3 github_secrets_hunter.py example.com ghp_xxxxxxxxxxxxxxxxxxxx")
        print("\nNote: GitHub token is optional but recommended for higher rate limits")
        sys.exit(1)
    
    target = sys.argv[1]
    github_token = sys.argv[2] if len(sys.argv) > 2 else None
    
    hunter = GitHubSecretsHunter(target, github_token)
    results = hunter.hunt_secrets()
    
    if results:
        print(f"\n🎯 SUCCESS: Found {len(results)} potential secrets!")
        print("⚠️  Remember to verify these findings and report responsibly!")
        print("💡 Check the generated files for detailed information.")
    else:
        print("\n❌ No secrets found for this target.")
        print("💡 Try different search terms or check manually.")

if __name__ == "__main__":
    main()