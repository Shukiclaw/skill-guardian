#!/usr/bin/env python3
"""
ClawdHub API Scanner - Downloads full skill packages via API
Uses official ClawdHub API to get all skill files
"""

import os
import sys
import json
import re
import urllib.request
import urllib.error
import ssl
import tempfile
import shutil
import tarfile
import io
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime

# API Configuration
CLAWDHUB_API = "https://clawhub.com/api/v1"
API_TOKEN = None

def load_token() -> str:
    """Load ClawdHub API token."""
    global API_TOKEN
    
    # Try multiple locations
    token_files = [
        os.path.expanduser("~/.config/clawdhub/token"),
        os.path.expanduser("~/.config/clawdhub/credentials.json"),
    ]
    
    for filepath in token_files:
        if os.path.exists(filepath):
            try:
                if filepath.endswith('.json'):
                    with open(filepath) as f:
                        data = json.load(f)
                        API_TOKEN = data.get('token')
                else:
                    with open(filepath) as f:
                        API_TOKEN = f.read().strip()
                
                if API_TOKEN:
                    print(f"✅ Loaded token from {filepath}")
                    return API_TOKEN
            except Exception as e:
                print(f"⚠️ Error loading {filepath}: {e}")
    
    raise ValueError("No ClawdHub API token found")

def api_request(endpoint: str, method="GET", data=None) -> Optional[dict]:
    """Make authenticated API request to ClawdHub."""
    url = f"{CLAWDHUB_API}{endpoint}"
    
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "SkillGuardian/1.0"
    }
    
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode() if data else None,
            headers=headers,
            method=method
        )
        
        # Create SSL context that verifies certificates
        context = ssl.create_default_context()
        
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
            else:
                print(f"⚠️ API error: {response.status}")
                return None
                
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"⚠️ Not found: {endpoint}")
        elif e.code == 401:
            print(f"❌ Unauthorized - check API token")
        else:
            print(f"⚠️ HTTP {e.code}: {e.reason}")
        return None
    except Exception as e:
        print(f"⚠️ Request error: {e}")
        return None

def get_skill_info(skill_slug: str) -> Optional[dict]:
    """Get skill metadata from API."""
    return api_request(f"/skills/{skill_slug}")

def get_skill_download_url(skill_slug: str, version: str = None) -> Optional[str]:
    """Get download URL for skill package."""
    # Try version-specific endpoint
    if version:
        info = api_request(f"/skills/{skill_slug}/versions/{version}")
    else:
        # Get latest version info
        info = get_skill_info(skill_slug)
    
    if info and 'latestVersion' in info:
        version = info['latestVersion'].get('version')
        
    # Construct download URL
    # Based on typical patterns: /skills/{slug}/download or /skills/{slug}/versions/{version}/download
    download_endpoints = [
        f"/skills/{skill_slug}/download",
        f"/skills/{skill_slug}/versions/{version}/download" if version else None,
        f"/skills/{skill_slug}/package",
    ]
    
    for endpoint in download_endpoints:
        if not endpoint:
            continue
        # Try HEAD request to check if endpoint exists
        try:
            req = urllib.request.Request(
                f"{CLAWDHUB_API}{endpoint}",
                headers={"Authorization": f"Bearer {API_TOKEN}"},
                method="HEAD"
            )
            context = ssl.create_default_context()
            with urllib.request.urlopen(req, context=context, timeout=10) as resp:
                if resp.status in [200, 302]:
                    return f"{CLAWDHUB_API}{endpoint}"
        except:
            continue
    
    # Fallback: return the most likely URL
    return f"{CLAWDHUB_API}/skills/{skill_slug}/download"

def download_skill_package(skill_slug: str, workdir: str, version: str = None) -> Optional[str]:
    """
    Download full skill package via API.
    Returns path to extracted skill directory.
    """
    print(f"  📥 Downloading {skill_slug} via API...")
    
    # Get download URL
    download_url = get_skill_download_url(skill_slug, version)
    if not download_url:
        print(f"  ❌ No download URL found")
        return None
    
    print(f"  📡 URL: {download_url[:60]}...")
    
    # Download package
    skill_dir = os.path.join(workdir, skill_slug)
    os.makedirs(skill_dir, exist_ok=True)
    
    try:
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "User-Agent": "SkillGuardian/1.0"
        }
        
        req = urllib.request.Request(download_url, headers=headers)
        context = ssl.create_default_context()
        
        with urllib.request.urlopen(req, context=context, timeout=60) as response:
            content_type = response.headers.get('Content-Type', '')
            data = response.read()
            
            # Determine format and extract
            if 'tar' in content_type or data[:4] == b'\x1f\x8b':  # gzip/tar
                package_file = os.path.join(workdir, f"{skill_slug}.tar.gz")
                with open(package_file, 'wb') as f:
                    f.write(data)
                
                # Extract
                with tarfile.open(package_file, 'r:gz') as tar:
                    tar.extractall(skill_dir)
                
                os.remove(package_file)
                
            elif 'zip' in content_type or data[:2] == b'PK':  # zip
                package_file = os.path.join(workdir, f"{skill_slug}.zip")
                with open(package_file, 'wb') as f:
                    f.write(data)
                
                # Extract
                import zipfile
                with zipfile.ZipFile(package_file, 'r') as zf:
                    zf.extractall(skill_dir)
                
                os.remove(package_file)
            else:
                # Try as tarball anyway
                try:
                    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
                        tar.extractall(skill_dir)
                except:
                    # Save as-is
                    package_file = os.path.join(skill_dir, "package")
                    with open(package_file, 'wb') as f:
                        f.write(data)
                    print(f"  ⚠️ Unknown format, saved as 'package'")
        
        # Check if extracted successfully
        if os.path.exists(os.path.join(skill_dir, "SKILL.md")):
            print(f"  ✅ Downloaded and extracted")
            return skill_dir
        else:
            # Try to find SKILL.md in subdirectories
            for root, dirs, files in os.walk(skill_dir):
                if "SKILL.md" in files:
                    return root
            
            print(f"  ⚠️ No SKILL.md found after extraction")
            return skill_dir  # Return anyway
            
    except Exception as e:
        print(f"  ❌ Download failed: {e}")
        return None

def list_all_skills() -> List[str]:
    """List all available skills from API."""
    print("🔍 Fetching skill list from API...")
    
    skills = []
    page = 1
    
    while True:
        result = api_request(f"/skills?page={page}&limit=100")
        
        if not result:
            break
        
        page_skills = result.get('items', result.get('skills', []))
        if not page_skills:
            break
        
        for skill in page_skills:
            skills.append(skill.get('slug'))
        
        print(f"  Page {page}: {len(skills)} total skills")
        
        # Check if there's more
        if len(page_skills) < 100:
            break
        
        page += 1
    
    return skills

# Import scanner from batch_scanner
import sys
sys.path.insert(0, os.path.dirname(__file__))
from batch_scanner import SkillScanner, Database, ScanResult, Finding

class APIScanner:
    """Scanner that uses ClawdHub API directly."""
    
    def __init__(self):
        load_token()
        self.scanner = SkillScanner()
        self.db = Database(os.path.expanduser("~/.openclaw/clawdhub-api-scan-db.json"))
    
    def scan_skill(self, skill_slug: str, workdir: str) -> ScanResult:
        """Scan a skill using API download."""
        print(f"🔍 Scanning: {skill_slug}")
        
        # Download via API
        skill_dir = download_skill_package(skill_slug, workdir)
        
        if not skill_dir:
            return ScanResult(
                skill=skill_slug,
                status='ERROR',
                findings=[],
                scanned_at=datetime.utcnow().isoformat(),
                error='Failed to download via API'
            )
        
        # Find actual skill root (might be nested)
        skill_root = skill_dir
        for root, dirs, files in os.walk(skill_dir):
            if "SKILL.md" in files:
                skill_root = root
                break
        
        # Scan SKILL.md
        findings = self.scanner.scan(os.path.join(skill_root, "SKILL.md"))
        
        # Scan all Python files in package
        for py_file in Path(skill_root).rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Quick pattern check for Python files
                dangerous_patterns = [
                    (r'\bexec\s*\(', 'CRITICAL', 'exec() in Python code'),
                    (r'\beval\s*\(', 'CRITICAL', 'eval() in Python code'),
                    (r'\bsubprocess\.', 'HIGH', 'subprocess in Python code'),
                    (r'\bos\.system\s*\(', 'HIGH', 'os.system() in Python code'),
                    (r'\bshell\s*=\s*True', 'CRITICAL', 'shell=True in Python code'),
                ]
                
                for pattern, severity, desc in dangerous_patterns:
                    if re.search(pattern, content):
                        findings.append(Finding(
                            file=str(py_file.relative_to(skill_root)),
                            line=1,
                            severity=severity,
                            description=desc
                        ))
            except:
                pass
        
        status = self.scanner.determine_status(findings)
        
        return ScanResult(
            skill=skill_slug,
            status=status,
            findings=findings,
            scanned_at=datetime.utcnow().isoformat()
        )
    
    def run_batch(self, skills: List[str]):
        """Run batch scan."""
        workdir = tempfile.mkdtemp(prefix='api-scan-')
        
        try:
            for skill in skills:
                result = self.scan_skill(skill, workdir)
                self.db.save_result(result)
                
                # Cleanup
                skill_dir = os.path.join(workdir, skill)
                if os.path.exists(skill_dir):
                    shutil.rmtree(skill_dir, ignore_errors=True)
                
                # Report
                if result.status == 'DANGEROUS':
                    print(f"  🚨 DANGEROUS - {len(result.findings)} findings")
                    for f in result.findings[:5]:
                        print(f"     [{f.severity}] {f.description}")
                elif result.status == 'SUSPICIOUS':
                    print(f"  ⚠️  SUSPICIOUS - {len(result.findings)} findings")
                else:
                    print(f"  ✅ SAFE")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='ClawdHub API Scanner')
    parser.add_argument('skill', nargs='?', help='Scan single skill')
    parser.add_argument('--list', action='store_true', help='List all skills')
    
    args = parser.parse_args()
    
    if args.list:
        skills = list_all_skills()
        print(f"\nTotal: {len(skills)} skills")
        for s in skills[:20]:
            print(f"  - {s}")
        if len(skills) > 20:
            print(f"  ... and {len(skills) - 20} more")
    elif args.skill:
        scanner = APIScanner()
        workdir = tempfile.mkdtemp()
        try:
            result = scanner.scan_skill(args.skill, workdir)
            print(f"\nStatus: {result.status}")
            print(f"Findings: {len(result.findings)}")
            for f in result.findings:
                print(f"  [{f.severity}] {f.description}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    else:
        print("Usage: api_scanner.py <skill> | --list")
        print("\nExamples:")
        print("  python3 api_scanner.py cocod")
        print("  python3 api_scanner.py --list")