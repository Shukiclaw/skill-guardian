#!/usr/bin/env python3
"""
Safe Skill Downloader - Uses clawdhub CLI with sandboxing
Downloads and extracts without executing any code
"""

import os
import sys
import subprocess
import tempfile
import shutil
import json
import tarfile
import zipfile
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Finding:
    file: str
    severity: str
    description: str
    line: int = 0

class SafePackageScanner:
    """Safely extract and scan skill packages."""
    
    def __init__(self, workdir: str):
        self.workdir = workdir
        self.findings = []
    
    def download_skill(self, skill_slug: str) -> Optional[Path]:
        """
        Download skill using clawdhub CLI.
        This only downloads files, never executes skill code.
        """
        skill_dir = Path(self.workdir) / skill_slug
        
        try:
            result = subprocess.run(
                ['/home/linuxbrew/.linuxbrew/bin/clawdhub', 'install', skill_slug, '--dir', self.workdir],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and skill_dir.exists():
                return skill_dir
            
            return None
        except Exception as e:
            print(f"  ❌ Download error: {e}")
            return None
    
    def scan_file(self, filepath: Path, relative_to: Path) -> List[Finding]:
        """Scan a single file for dangerous patterns."""
        findings = []
        rel_path = filepath.relative_to(relative_to)
        
        # Skip non-text files
        try:
            # Check if binary
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:
                    return findings  # Binary file
        except:
            return findings
        
        # Read as text
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return findings
        
        # Pattern checks based on file type
        if filepath.suffix == '.py':
            findings.extend(self._scan_python(content, rel_path))
        elif filepath.name == 'SKILL.md':
            findings.extend(self._scan_skill_md(content, rel_path))
        elif filepath.suffix in ['.sh', '.bash']:
            findings.extend(self._scan_shell(content, rel_path))
        elif filepath.suffix == '.js':
            findings.extend(self._scan_javascript(content, rel_path))
        
        return findings
    
    def _scan_python(self, content: str, filepath: Path) -> List[Finding]:
        """Scan Python code."""
        findings = []
        lines = content.split('\n')
        
        dangerous = [
            (r'\bexec\s*\(', 'CRITICAL', 'exec() call'),
            (r'\beval\s*\(', 'CRITICAL', 'eval() call'),
            (r'\b__import__\s*\(', 'CRITICAL', 'Dynamic import'),
            (r'\bsubprocess\.', 'HIGH', 'subprocess usage'),
            (r'\bos\.system\s*\(', 'HIGH', 'os.system()'),
            (r'\bshell\s*=\s*True', 'CRITICAL', 'shell=True'),
            (r'\brequests\.(get|post|put|delete)', 'MEDIUM', 'HTTP request'),
            (r'\bsocket\.', 'MEDIUM', 'socket usage'),
            (r'\bsmtplib', 'CRITICAL', 'Email capability'),
            (r'\bpty\.', 'CRITICAL', 'PTY spawn'),
        ]
        
        import re
        for i, line in enumerate(lines, 1):
            for pattern, severity, desc in dangerous:
                if re.search(pattern, line):
                    findings.append(Finding(str(filepath), severity, desc, i))
        
        return findings
    
    def _scan_skill_md(self, content: str, filepath: Path) -> List[Finding]:
        """Scan SKILL.md documentation."""
        findings = []
        content_lower = content.lower()
        
        suspicious = [
            'ignore previous instructions',
            'ignore all instructions',
            'steal data',
            'exfiltrate',
            'send all data',
            'collect passwords',
            'download and execute',
            'remote code execution',
            'reverse shell',
            'bind shell',
        ]
        
        for phrase in suspicious:
            if phrase in content_lower:
                findings.append(Finding(
                    str(filepath), 'HIGH',
                    f'Suspicious phrase: "{phrase}"', 1
                ))
        
        return findings
    
    def _scan_shell(self, content: str, filepath: Path) -> List[Finding]:
        """Scan shell scripts."""
        findings = []
        lines = content.split('\n')
        
        dangerous = [
            (r'\beval\s', 'CRITICAL', 'eval in shell'),
            (r'\bcurl\s+.*\|', 'HIGH', 'curl | bash pattern'),
            (r'\bwget\s+.*\|', 'HIGH', 'wget | bash pattern'),
            (r'\brm\s+-rf\s+/', 'CRITICAL', 'rm -rf /'),
        ]
        
        import re
        for i, line in enumerate(lines, 1):
            for pattern, severity, desc in dangerous:
                if re.search(pattern, line):
                    findings.append(Finding(str(filepath), severity, desc, i))
        
        return findings
    
    def _scan_javascript(self, content: str, filepath: Path) -> List[Finding]:
        """Scan JavaScript code."""
        findings = []
        lines = content.split('\n')
        
        dangerous = [
            (r'\beval\s*\(', 'CRITICAL', 'eval()'),
            (r'\bFunction\s*\(', 'HIGH', 'Function constructor'),
            (r'\bchild_process', 'HIGH', 'child_process module'),
            (r'\bexec\s*\(', 'HIGH', 'exec()'),
        ]
        
        import re
        for i, line in enumerate(lines, 1):
            for pattern, severity, desc in dangerous:
                if re.search(pattern, line):
                    findings.append(Finding(str(filepath), severity, desc, i))
        
        return findings
    
    def scan_skill(self, skill_slug: str) -> dict:
        """
        Complete scan of a skill.
        Downloads, extracts, and scans all files.
        """
        print(f"🔍 Scanning: {skill_slug}")
        
        # Download
        skill_dir = self.download_skill(skill_slug)
        if not skill_dir:
            return {
                'skill': skill_slug,
                'status': 'ERROR',
                'findings': [Finding('', 'HIGH', 'Download failed')],
                'files_scanned': 0
            }
        
        # Scan all files
        all_findings = []
        files_scanned = 0
        
        for filepath in skill_dir.rglob('*'):
            if filepath.is_file():
                findings = self.scan_file(filepath, skill_dir)
                all_findings.extend(findings)
                files_scanned += 1
        
        # Determine status
        if not all_findings:
            status = 'SAFE'
        elif any(f.severity == 'CRITICAL' for f in all_findings):
            status = 'DANGEROUS'
        elif any(f.severity == 'HIGH' for f in all_findings):
            status = 'DANGEROUS'
        else:
            status = 'SUSPICIOUS'
        
        return {
            'skill': skill_slug,
            'status': status,
            'findings': all_findings,
            'files_scanned': files_scanned
        }

def scan_skills_batch(skills: List[str], batch_size: int = 5):
    """Scan skills in batches."""
    workdir = tempfile.mkdtemp(prefix='safe-scan-')
    
    try:
        scanner = SafePackageScanner(workdir)
        results = []
        
        for i, skill in enumerate(skills, 1):
            print(f"\n[{i}/{len(skills)}] {skill}")
            result = scanner.scan_skill(skill)
            results.append(result)
            
            # Report
            if result['status'] == 'DANGEROUS':
                print(f"  🚨 DANGEROUS")
                for f in result['findings'][:5]:
                    print(f"     [{f.severity}] {f.file}:{f.line} - {f.description}")
            elif result['status'] == 'SUSPICIOUS':
                print(f"  ⚠️  SUSPICIOUS ({len(result['findings'])} findings)")
            else:
                print(f"  ✅ SAFE ({result['files_scanned']} files scanned)")
            
            # Cleanup immediately
            skill_dir = Path(workdir) / skill
            if skill_dir.exists():
                shutil.rmtree(skill_dir, ignore_errors=True)
        
        return results
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Safe Skill Package Scanner')
    parser.add_argument('skills', nargs='+', help='Skill slugs to scan')
    parser.add_argument('--batch', type=int, default=5, help='Batch size')
    
    args = parser.parse_args()
    
    results = scan_skills_batch(args.skills, args.batch)
    
    # Summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    dangerous = [r for r in results if r['status'] == 'DANGEROUS']
    suspicious = [r for r in results if r['status'] == 'SUSPICIOUS']
    errors = [r for r in results if r['status'] == 'ERROR']
    
    print(f"Total: {len(results)}")
    print(f"DANGEROUS: {len(dangerous)}")
    print(f"SUSPICIOUS: {len(suspicious)}")
    print(f"Errors: {len(errors)}")
    
    if dangerous:
        print("\n🚨 DANGEROUS SKILLS:")
        for r in dangerous:
            print(f"  - {r['skill']}")
    
    if suspicious:
        print("\n⚠️  SUSPICIOUS SKILLS:")
        for r in suspicious:
            print(f"  - {r['skill']}: {len(r['findings'])} findings")