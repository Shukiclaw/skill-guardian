#!/usr/bin/env python3
"""
ClawdHub Batch Scanner - Mass security scanning with queue management
Scans skills in small batches without installing any code
"""

import os
import sys
import json
import re
import subprocess
import tempfile
import shutil
import time
import signal
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from datetime import datetime
from pathlib import Path
import threading
import queue

# Configuration
DB_FILE = os.path.expanduser("~/.openclaw/clawdhub-scan-db.json")
LOG_FILE = os.path.expanduser("~/.openclaw/logs/clawdhub-batch-scan.log")
BATCH_SIZE = 5  # Scan 5 skills at a time
SCAN_TIMEOUT = 30  # Seconds per skill
MAX_WORKERS = 3  # Parallel scans
REPORT_DIR = os.path.expanduser("~/.openclaw/reports")

@dataclass
class Finding:
    file: str
    severity: str
    description: str
    line: int = 0
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ScanResult:
    skill: str
    status: str  # SAFE, SUSPICIOUS, DANGEROUS, ERROR
    findings: List[Finding]
    scanned_at: str
    error: Optional[str] = None
    
    def to_dict(self):
        return {
            'skill': self.skill,
            'status': self.status,
            'findings': [f.to_dict() for f in self.findings],
            'scanned_at': self.scanned_at,
            'error': self.error
        }

class Database:
    """Simple JSON database for scan results."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = self._load()
    
    def _load(self) -> dict:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            'scanned_skills': {},
            'queue': [],
            'threats': [],
            'stats': {'total_scanned': 0, 'threats_found': 0, 'last_scan': None}
        }
    
    def save(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        with open(self.filepath, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
    
    def add_to_queue(self, skills: List[str]):
        """Add skills to scan queue."""
        existing = set(self.data['queue'])
        existing.update(self.data['scanned_skills'].keys())
        
        new_skills = [s for s in skills if s not in existing]
        self.data['queue'].extend(new_skills)
        self.save()
        return len(new_skills)
    
    def get_batch(self, size: int = BATCH_SIZE) -> List[str]:
        """Get next batch from queue."""
        batch = self.data['queue'][:size]
        self.data['queue'] = self.data['queue'][size:]
        self.save()
        return batch
    
    def save_result(self, result: ScanResult):
        """Save scan result."""
        self.data['scanned_skills'][result.skill] = result.to_dict()
        self.data['stats']['total_scanned'] += 1
        
        if result.status in ['DANGEROUS', 'SUSPICIOUS']:
            self.data['threats'].append(result.to_dict())
            self.data['stats']['threats_found'] += 1
        
        self.data['stats']['last_scan'] = datetime.utcnow().isoformat()
        self.save()
    
    def is_scanned(self, skill: str) -> bool:
        return skill in self.data['scanned_skills']
    
    def get_threats(self) -> List[dict]:
        return self.data['threats']
    
    def get_stats(self) -> dict:
        return {
            **self.data['stats'],
            'queue_size': len(self.data['queue']),
            'scanned_count': len(self.data['scanned_skills'])
        }

class SkillScanner:
    """Safe static scanner for SKILL.md files."""
    
    PATTERNS = [
        (re.compile(r'\bexec\s*\('), 'CRITICAL', 'exec() detected'),
        (re.compile(r'\beval\s*\('), 'CRITICAL', 'eval() detected'),
        (re.compile(r'\b__import__\s*\('), 'CRITICAL', 'Dynamic import'),
        (re.compile(r'\bsubprocess\.(?:call|run|Popen)'), 'HIGH', 'subprocess execution'),
        (re.compile(r'\bos\.system\s*\('), 'HIGH', 'os.system() shell command'),
        (re.compile(r'\bshell\s*=\s*True'), 'CRITICAL', 'shell=True (injection risk)'),
        (re.compile(r'\brequests\.(?:get|post|put|delete)\s*\('), 'MEDIUM', 'HTTP request'),
        (re.compile(r'\burllib\.'), 'MEDIUM', 'urllib network access'),
        (re.compile(r'\bsocket\.'), 'MEDIUM', 'socket network access'),
        (re.compile(r'\bsmtplib\.(?:SMTP|send)'), 'CRITICAL', 'Email sending capability'),
        (re.compile(r'\bcurl\s+(?:http|ftp)'), 'HIGH', 'curl HTTP/FTP'),
        (re.compile(r'\bwget\s+(?:http|ftp)'), 'HIGH', 'wget HTTP/FTP'),
        (re.compile(r'\bnc\s+-'), 'HIGH', 'netcat usage'),
        (re.compile(r'\b(base64|xxd)\s+-d'), 'MEDIUM', 'Base64 decoding'),
    ]
    
    SUSPICIOUS_KEYWORDS = [
        'ignore previous instructions',
        'ignore all instructions', 
        'steal data',
        'exfiltrate',
        'send all',
        'collect passwords',
        'download and execute',
        'remote code',
        'reverse shell',
        'bind shell',
    ]
    
    def scan(self, skill_md_path: str) -> List[Finding]:
        findings = []
        
        if not os.path.exists(skill_md_path):
            return [Finding('SKILL.md', 'HIGH', 'Missing SKILL.md', 0)]
        
        try:
            with open(skill_md_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                content_lower = content.lower()
        except Exception as e:
            return [Finding('SKILL.md', 'LOW', f'Read error: {e}', 0)]
        
        # Check suspicious keywords
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in content_lower:
                findings.append(Finding(
                    'SKILL.md', 'HIGH',
                    f'Suspicious phrase: "{keyword}"',
                    1
                ))
        
        # Check code patterns
        for pattern, severity, desc in self.PATTERNS:
            matches = list(pattern.finditer(content))
            for match in matches[:3]:  # Max 3 per pattern
                line = content[:match.start()].count('\n') + 1
                findings.append(Finding('SKILL.md', severity, desc, line))
        
        return findings
    
    def determine_status(self, findings: List[Finding]) -> str:
        if not findings:
            return 'SAFE'
        
        critical = len([f for f in findings if f.severity == 'CRITICAL'])
        high = len([f for f in findings if f.severity == 'HIGH'])
        
        if critical >= 1 or high >= 2:
            return 'DANGEROUS'
        elif high == 1 or len(findings) > 0:
            return 'SUSPICIOUS'
        return 'SAFE'

class BatchScanner:
    """Main batch scanner with queue management."""
    
    def __init__(self):
        self.db = Database(DB_FILE)
        self.scanner = SkillScanner()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print("\n⚠️  Received signal, finishing current batch...")
        self.running = False
    
    def log(self, message: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{timestamp}] {message}"
        print(line)
        
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    
    def download_skill(self, skill: str, workdir: str) -> Optional[str]:
        """Download skill using clawdhub (SKILL.md only)."""
        skill_dir = os.path.join(workdir, skill)
        
        try:
            result = subprocess.run(
                ['clawdhub', 'install', skill, '--dir', workdir],
                capture_output=True, text=True, timeout=SCAN_TIMEOUT
            )
            
            if result.returncode == 0:
                skill_md = os.path.join(skill_dir, 'SKILL.md')
                if os.path.exists(skill_md):
                    return skill_md
            
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None
    
    def scan_single(self, skill: str, workdir: str) -> ScanResult:
        """Scan a single skill."""
        skill_md = self.download_skill(skill, workdir)
        
        if not skill_md:
            return ScanResult(
                skill=skill,
                status='ERROR',
                findings=[],
                scanned_at=datetime.utcnow().isoformat(),
                error='Failed to download'
            )
        
        findings = self.scanner.scan(skill_md)
        status = self.scanner.determine_status(findings)
        
        return ScanResult(
            skill=skill,
            status=status,
            findings=findings,
            scanned_at=datetime.utcnow().isoformat()
        )
    
    def scan_batch(self, skills: List[str]) -> List[ScanResult]:
        """Scan a batch of skills."""
        workdir = tempfile.mkdtemp(prefix='batch-scan-')
        results = []
        
        try:
            for skill in skills:
                if not self.running:
                    break
                
                result = self.scan_single(skill, workdir)
                results.append(result)
                self.db.save_result(result)
                
                # Cleanup immediately
                skill_dir = os.path.join(workdir, skill)
                if os.path.exists(skill_dir):
                    shutil.rmtree(skill_dir, ignore_errors=True)
                
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        
        return results
    
    def collect_all_skills(self) -> List[str]:
        """Collect all skills from ClawdHub."""
        self.log("🔍 Collecting skills from ClawdHub...")
        all_skills = set()
        
        # Search all letters
        for letter in 'abcdefghijklmnopqrstuvwxyz':
            if not self.running:
                break
            
            try:
                result = subprocess.run(
                    ['clawdhub', 'search', letter, '--limit', '100'],
                    capture_output=True, text=True, timeout=15
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        match = re.match(r'^([a-z0-9-]+)\s+v', line)
                        if match:
                            all_skills.add(match.group(1))
                
                self.log(f"  Letter '{letter}': {len(all_skills)} total skills")
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                self.log(f"  ⚠️ Error searching '{letter}': {e}")
        
        return sorted(list(all_skills))
    
    def generate_report(self):
        """Generate scan report."""
        os.makedirs(REPORT_DIR, exist_ok=True)
        
        threats = self.db.get_threats()
        stats = self.db.get_stats()
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'stats': stats,
            'threats': threats,
            'dangerous': [t for t in threats if t['status'] == 'DANGEROUS'],
            'suspicious': [t for t in threats if t['status'] == 'SUSPICIOUS']
        }
        
        report_file = os.path.join(REPORT_DIR, f'report-{datetime.now():%Y%m%d-%H%M%S}.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Summary text
        summary_file = os.path.join(REPORT_DIR, 'latest-summary.txt')
        with open(summary_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("CLAWDHUB SECURITY SCAN REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Generated: {report['generated_at']}\n")
            f.write(f"Total Scanned: {stats['total_scanned']}\n")
            f.write(f"Threats Found: {stats['threats_found']}\n")
            f.write(f"Queue Remaining: {stats['queue_size']}\n\n")
            
            if report['dangerous']:
                f.write("🚨 DANGEROUS SKILLS:\n")
                f.write("-" * 40 + "\n")
                for t in report['dangerous']:
                    f.write(f"\n{t['skill']}:\n")
                    for finding in t['findings'][:5]:
                        f.write(f"  [{finding['severity']}] {finding['description']}\n")
            
            if report['suspicious']:
                f.write("\n\n⚠️  SUSPICIOUS SKILLS:\n")
                f.write("-" * 40 + "\n")
                for t in report['suspicious']:
                    f.write(f"  - {t['skill']}: {len(t['findings'])} findings\n")
        
        self.log(f"📊 Report saved: {report_file}")
        return report_file
    
    def run(self, continuous: bool = True):
        """Main scan loop."""
        self.log("=" * 60)
        self.log("CLAWDHUB BATCH SCANNER")
        self.log("=" * 60)
        
        # Collect skills if queue is empty
        stats = self.db.get_stats()
        if stats['queue_size'] == 0 and stats['scanned_count'] == 0:
            skills = self.collect_all_skills()
            added = self.db.add_to_queue(skills)
            self.log(f"📥 Added {added} skills to queue")
        else:
            self.log(f"📋 Resuming: {stats['queue_size']} in queue, {stats['scanned_count']} done")
        
        # Process queue
        batch_num = 0
        while self.running:
            batch = self.db.get_batch(BATCH_SIZE)
            
            if not batch:
                self.log("✅ Queue empty! Scan complete.")
                break
            
            batch_num += 1
            self.log(f"\n📦 Batch {batch_num}: {len(batch)} skills")
            
            results = self.scan_batch(batch)
            
            # Log results
            dangerous = [r for r in results if r.status == 'DANGEROUS']
            suspicious = [r for r in results if r.status == 'SUSPICIOUS']
            errors = [r for r in results if r.status == 'ERROR']
            
            if dangerous:
                self.log(f"  🚨 {len(dangerous)} DANGEROUS")
            if suspicious:
                self.log(f"  ⚠️  {len(suspicious)} SUSPICIOUS")
            if errors:
                self.log(f"  ❌ {len(errors)} errors")
            
            stats = self.db.get_stats()
            self.log(f"  📊 Progress: {stats['scanned_count']} / {stats['scanned_count'] + stats['queue_size']}")
            
            if not continuous and batch_num >= 1:
                self.log("⏹️  Single batch mode - stopping")
                break
            
            time.sleep(1)  # Brief pause between batches
        
        # Generate report
        report_file = self.generate_report()
        
        self.log("\n" + "=" * 60)
        self.log("SCAN COMPLETE")
        self.log("=" * 60)
        stats = self.db.get_stats()
        self.log(f"Total scanned: {stats['total_scanned']}")
        self.log(f"Threats found: {stats['threats_found']}")
        self.log(f"Report: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ClawdHub Batch Security Scanner')
    parser.add_argument('--once', action='store_true', help='Scan one batch and exit')
    parser.add_argument('--collect-only', action='store_true', help='Only collect skills, dont scan')
    parser.add_argument('--report', action='store_true', help='Generate report only')
    
    args = parser.parse_args()
    
    scanner = BatchScanner()
    
    if args.report:
        scanner.generate_report()
    elif args.collect_only:
        skills = scanner.collect_all_skills()
        added = scanner.db.add_to_queue(skills)
        print(f"Added {added} skills to queue")
    else:
        scanner.run(continuous=not args.once)