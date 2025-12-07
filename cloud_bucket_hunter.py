#!/usr/bin/env python3
"""
Elite Cloud Storage Bucket Hunter
AWS S3, Google Cloud, Azure Blob Storage Discovery
Red Team OSINT Tool - Free Version
"""

import requests
import concurrent.futures
import time
import sys
import json
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from threading import Lock

class CloudBucketHunter:
    def __init__(self, target):
        self.target = target
        self.company_name = target.split('.')[0]
        self.found_buckets = []
        self.lock = Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                  ☁️  ELITE CLOUD BUCKET HUNTER ☁️            ║
║                    AWS S3 | GCS | Azure Blob                ║
║                      Red Team OSINT Tool                    ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def generate_bucket_names(self):
        """Generate potential bucket names"""
        print(f"[+] Generating bucket names for: {self.target}")
        
        base_names = [
            self.company_name,
            self.company_name.lower(),
            self.company_name.upper(),
            self.target.replace('.', '-'),
            self.target.replace('.', '_'),
            self.target.replace('.', ''),
        ]
        
        # Common suffixes and prefixes
        suffixes = [
            '', '-backup', '-backups', '-bak', '-old', '-new',
            '-dev', '-development', '-test', '-testing', '-stage', '-staging',
            '-prod', '-production', '-live', '-www', '-web', '-site',
            '-assets', '-static', '-files', '-data', '-db', '-database',
            '-logs', '-log', '-uploads', '-images', '-img', '-pics',
            '-documents', '-docs', '-reports', '-temp', '-tmp',
            '-archive', '-archives', '-storage', '-store', '-media',
            '-public', '-private', '-internal', '-external', '-admin',
            '-user', '-users', '-client', '-clients', '-customer',
            '-app', '-application', '-api', '-cdn', '-cache',
            '-config', '-configuration', '-settings', '-backup2021',
            '-backup2022', '-backup2023', '-backup2024', '-backup2025',
            '2021', '2022', '2023', '2024', '2025', '-old2021',
            '-v1', '-v2', '-v3', '-beta', '-alpha', '-release'
        ]
        
        prefixes = [
            '', 'www-', 'web-', 'app-', 'api-', 'cdn-', 'static-',
            'assets-', 'files-', 'data-', 'backup-', 'temp-',
            'dev-', 'test-', 'prod-', 'staging-', 'demo-'
        ]
        
        bucket_names = set()
        
        for base in base_names:
            for prefix in prefixes:
                for suffix in suffixes:
                    name = f"{prefix}{base}{suffix}"
                    if len(name) >= 3 and len(name) <= 63:  # AWS S3 naming rules
                        bucket_names.add(name.lower())
        
        print(f"[✓] Generated {len(bucket_names)} potential bucket names")
        return list(bucket_names)
    
    def check_aws_s3_bucket(self, bucket_name):
        """Check AWS S3 bucket existence and permissions"""
        urls_to_check = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
            f"https://{bucket_name}.s3-us-west-2.amazonaws.com",
            f"https://{bucket_name}.s3-us-east-1.amazonaws.com",
            f"https://{bucket_name}.s3-eu-west-1.amazonaws.com",
            f"https://{bucket_name}.s3-ap-southeast-1.amazonaws.com"
        ]
        
        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # Bucket exists and is readable
                    content_type = response.headers.get('content-type', '')
                    if 'xml' in content_type.lower():
                        try:
                            root = ET.fromstring(response.text)
                            files = []
                            for content in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                                key = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                                size = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size')
                                if key is not None:
                                    files.append({
                                        'key': key.text,
                                        'size': size.text if size is not None else 'Unknown'
                                    })
                            
                            bucket_info = {
                                'name': bucket_name,
                                'url': url,
                                'provider': 'AWS S3',
                                'status': 'Public Read',
                                'files_count': len(files),
                                'files': files[:10],  # First 10 files
                                'response_size': len(response.text)
                            }
                            
                            with self.lock:
                                self.found_buckets.append(bucket_info)
                            
                            print(f"[🎯] FOUND: {url} - Public Read Access ({len(files)} files)")
                            return bucket_info
                            
                        except ET.ParseError:
                            pass
                
                elif response.status_code == 403:
                    # Bucket exists but access denied
                    bucket_info = {
                        'name': bucket_name,
                        'url': url,
                        'provider': 'AWS S3',
                        'status': 'Access Denied (Bucket Exists)',
                        'files_count': 0,
                        'files': [],
                        'response_size': len(response.text)
                    }
                    
                    with self.lock:
                        self.found_buckets.append(bucket_info)
                    
                    print(f"[⚠️] FOUND: {url} - Access Denied (Bucket Exists)")
                    return bucket_info
                    
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def check_gcs_bucket(self, bucket_name):
        """Check Google Cloud Storage bucket"""
        urls_to_check = [
            f"https://storage.googleapis.com/{bucket_name}",
            f"https://{bucket_name}.storage.googleapis.com",
            f"https://storage.cloud.google.com/{bucket_name}"
        ]
        
        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        files = []
                        if 'items' in data:
                            for item in data['items'][:10]:
                                files.append({
                                    'key': item.get('name', 'Unknown'),
                                    'size': item.get('size', 'Unknown')
                                })
                        
                        bucket_info = {
                            'name': bucket_name,
                            'url': url,
                            'provider': 'Google Cloud Storage',
                            'status': 'Public Read',
                            'files_count': len(data.get('items', [])),
                            'files': files,
                            'response_size': len(response.text)
                        }
                        
                        with self.lock:
                            self.found_buckets.append(bucket_info)
                        
                        print(f"[🎯] FOUND: {url} - Public Read Access")
                        return bucket_info
                        
                    except json.JSONDecodeError:
                        pass
                
                elif response.status_code == 403:
                    bucket_info = {
                        'name': bucket_name,
                        'url': url,
                        'provider': 'Google Cloud Storage',
                        'status': 'Access Denied (Bucket Exists)',
                        'files_count': 0,
                        'files': [],
                        'response_size': len(response.text)
                    }
                    
                    with self.lock:
                        self.found_buckets.append(bucket_info)
                    
                    print(f"[⚠️] FOUND: {url} - Access Denied (Bucket Exists)")
                    return bucket_info
                    
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def check_azure_blob(self, container_name):
        """Check Azure Blob Storage container"""
        # Common Azure storage account patterns
        storage_accounts = [
            self.company_name,
            f"{self.company_name}storage",
            f"{self.company_name}data",
            f"{self.company_name}files",
            f"storage{self.company_name}",
            f"data{self.company_name}",
            f"files{self.company_name}"
        ]
        
        for account in storage_accounts:
            url = f"https://{account}.blob.core.windows.net/{container_name}?restype=container&comp=list"
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        root = ET.fromstring(response.text)
                        files = []
                        for blob in root.findall('.//Blob'):
                            name_elem = blob.find('.//Name')
                            size_elem = blob.find('.//Content-Length')
                            if name_elem is not None:
                                files.append({
                                    'key': name_elem.text,
                                    'size': size_elem.text if size_elem is not None else 'Unknown'
                                })
                        
                        bucket_info = {
                            'name': f"{account}/{container_name}",
                            'url': url,
                            'provider': 'Azure Blob Storage',
                            'status': 'Public Read',
                            'files_count': len(files),
                            'files': files[:10],
                            'response_size': len(response.text)
                        }
                        
                        with self.lock:
                            self.found_buckets.append(bucket_info)
                        
                        print(f"[🎯] FOUND: {url} - Public Read Access")
                        return bucket_info
                        
                    except ET.ParseError:
                        pass
                
                elif response.status_code == 403:
                    bucket_info = {
                        'name': f"{account}/{container_name}",
                        'url': url,
                        'provider': 'Azure Blob Storage',
                        'status': 'Access Denied (Container Exists)',
                        'files_count': 0,
                        'files': [],
                        'response_size': len(response.text)
                    }
                    
                    with self.lock:
                        self.found_buckets.append(bucket_info)
                    
                    print(f"[⚠️] FOUND: {url} - Access Denied (Container Exists)")
                    return bucket_info
                    
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def check_digital_ocean_spaces(self, space_name):
        """Check DigitalOcean Spaces"""
        regions = ['nyc3', 'ams3', 'sgp1', 'sfo2', 'fra1']
        
        for region in regions:
            url = f"https://{space_name}.{region}.digitaloceanspaces.com"
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    bucket_info = {
                        'name': space_name,
                        'url': url,
                        'provider': 'DigitalOcean Spaces',
                        'status': 'Public Read',
                        'files_count': 'Unknown',
                        'files': [],
                        'response_size': len(response.text)
                    }
                    
                    with self.lock:
                        self.found_buckets.append(bucket_info)
                    
                    print(f"[🎯] FOUND: {url} - Public Read Access")
                    return bucket_info
                
                elif response.status_code == 403:
                    bucket_info = {
                        'name': space_name,
                        'url': url,
                        'provider': 'DigitalOcean Spaces',
                        'status': 'Access Denied (Space Exists)',
                        'files_count': 0,
                        'files': [],
                        'response_size': len(response.text)
                    }
                    
                    with self.lock:
                        self.found_buckets.append(bucket_info)
                    
                    print(f"[⚠️] FOUND: {url} - Access Denied (Space Exists)")
                    return bucket_info
                    
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def check_bucket(self, bucket_name):
        """Check bucket across all cloud providers"""
        results = []
        
        # Check AWS S3
        aws_result = self.check_aws_s3_bucket(bucket_name)
        if aws_result:
            results.append(aws_result)
        
        # Check Google Cloud Storage
        gcs_result = self.check_gcs_bucket(bucket_name)
        if gcs_result:
            results.append(gcs_result)
        
        # Check Azure Blob Storage
        azure_result = self.check_azure_blob(bucket_name)
        if azure_result:
            results.append(azure_result)
        
        # Check DigitalOcean Spaces
        do_result = self.check_digital_ocean_spaces(bucket_name)
        if do_result:
            results.append(do_result)
        
        return results
    
    def hunt_buckets(self, max_workers=50):
        """Main bucket hunting function"""
        self.banner()
        print(f"[+] Starting cloud bucket hunting for: {self.target}")
        print(f"[+] Company name extracted: {self.company_name}")
        print(f"[+] Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        bucket_names = self.generate_bucket_names()
        
        print(f"[+] Testing {len(bucket_names)} bucket names across multiple cloud providers...")
        print(f"[+] Using {max_workers} concurrent threads")
        print("="*60)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.check_bucket, bucket_names)
        
        print("="*60)
        print(f"[✓] Bucket hunting completed!")
        print(f"[✓] Found {len(self.found_buckets)} accessible buckets/containers")
        
        if self.found_buckets:
            print("\n🎯 DISCOVERED BUCKETS:")
            for bucket in self.found_buckets:
                print(f"  • {bucket['provider']}: {bucket['url']}")
                print(f"    Status: {bucket['status']}")
                if bucket['files_count'] > 0:
                    print(f"    Files: {bucket['files_count']}")
                print()
        
        self.save_results()
        return self.found_buckets
    
    def save_results(self):
        """Save results to files"""
        if not self.found_buckets:
            print("[!] No buckets found to save")
            return
        
        # Save detailed JSON results
        with open(f'{self.target}_cloud_buckets.json', 'w') as f:
            json.dump({
                'target': self.target,
                'company_name': self.company_name,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_found': len(self.found_buckets),
                'buckets': self.found_buckets
            }, f, indent=2)
        
        # Save simple text list
        with open(f'{self.target}_cloud_buckets.txt', 'w') as f:
            f.write(f"Cloud Bucket Discovery Results for {self.target}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Found: {len(self.found_buckets)}\n")
            f.write("="*60 + "\n\n")
            
            for bucket in self.found_buckets:
                f.write(f"Provider: {bucket['provider']}\n")
                f.write(f"URL: {bucket['url']}\n")
                f.write(f"Status: {bucket['status']}\n")
                f.write(f"Files Count: {bucket['files_count']}\n")
                
                if bucket['files']:
                    f.write("Sample Files:\n")
                    for file_info in bucket['files']:
                        f.write(f"  - {file_info['key']} ({file_info['size']} bytes)\n")
                
                f.write("\n" + "-"*40 + "\n\n")
        
        print(f"[✓] Results saved to:")
        print(f"    • {self.target}_cloud_buckets.json")
        print(f"    • {self.target}_cloud_buckets.txt")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cloud_bucket_hunter.py <target_domain>")
        print("Example: python3 cloud_bucket_hunter.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    hunter = CloudBucketHunter(target)
    results = hunter.hunt_buckets()
    
    if results:
        print(f"\n🎯 SUCCESS: Found {len(results)} accessible cloud storage buckets!")
        print("⚠️  Remember to test these findings responsibly and ethically!")
    else:
        print("\n❌ No accessible buckets found for this target.")
        print("💡 Try different naming patterns or check manually.")

if __name__ == "__main__":
    main()