#!/usr/bin/env python3
"""
Skill Scanner - Universal security scanner for AI agent skills
Scans skill packages for dangerous patterns without executing code.

Usage:
    python3 skill_scanner.py /path/to/skills/
    python3 skill_scanner.py --report /path/to/skills/
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from datetime import datetime

__version__ = "1.0.0"

@dataclass
class Finding:
    """A security finding from scanning."""
    file: str
    line: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    code_snippet: str = ""
    
    def to_dict(self):
        return asdict(self)

class SkillScanner:
    """
    Static security analyzer for skill packages.
    Supports Python, JavaScript, TypeScript, Shell, and SKILL.md files.
    """
    
    # Python dangerous patterns
    PYTHON_PATTERNS = [
        (re.compile(r'\bexec\s*\('), 'CRITICAL', 'exec() - dynamic code execution'),
        (re.compile(r'\beval\s*\('), 'CRITICAL', 'eval() - dynamic code evaluation'),
        (re.compile(r'\b__import__\s*\('), 'CRITICAL', '__import__() - dynamic import'),
        (re.compile(r'\bsubprocess\.(?:call|run|Popen|check_output)'), 'HIGH', 'subprocess execution'),
        (re.compile(r'\bos\.system\s*\('), 'HIGH', 'os.system() shell command'),
        (re.compile(r'\bos\.popen'), 'HIGH', 'os.popen() shell execution'),
        (re.compile(r'\bshell\s*=\s*True'), 'CRITICAL', 'shell=True injection risk'),
        (re.compile(r'\bpty\.(?:spawn|openpty)'), 'CRITICAL', 'PTY spawn'),
        (re.compile(r'\bcompile\s*\('), 'MEDIUM', 'compile() code object'),
        (re.compile(r'\btypes\.CodeType'), 'HIGH', 'CodeType low-level code'),
        (re.compile(r'\bimportlib\.(?:import_module|reload)'), 'MEDIUM', 'Dynamic import'),
    ]
    
    # Network patterns
    NETWORK_PATTERNS = [
        (re.compile(r'\brequests\.(?:get|post|put|delete|patch|request)\s*\('), 'MEDIUM', 'HTTP request'),
        (re.compile(r'\burllib\.(?:request|urlopen)'), 'MEDIUM', 'urllib network access'),
        (re.compile(r'\bhttp\.client'), 'MEDIUM', 'HTTP client'),
        (re.compile(r'\bsocket\.(?:socket|create_connection|connect)'), 'MEDIUM', 'socket network access'),
        (re.compile(r'\bsmtplib\.(?:SMTP|SMTP_SSL|send)'), 'CRITICAL', 'Email sending capability'),
        (re.compile(r'\bftplib'), 'HIGH', 'FTP access'),
        (re.compile(r'\btelnetlib'), 'CRITICAL', 'Telnet access'),
    ]
    
    # File operation patterns
    FILE_PATTERNS = [
        (re.compile(r'\bopen\s*\([^)]*[\'"][wa]'), 'MEDIUM', 'File write operation'),
        (re.compile(r'\bos\.remove\s*\('), 'MEDIUM', 'File deletion'),
        (re.compile(r'\bos\.rmdir\s*\('), 'MEDIUM', 'Directory deletion'),
        (re.compile(r'\bshutil\.(?:rmtree|move|copy)'), 'MEDIUM', 'shutil file operations'),
        (re.compile(r'\bpathlib.*\.(?:write|unlink)'), 'MEDIUM', 'Path write/delete'),
    ]
    
    # System patterns
    SYSTEM_PATTERNS = [
        (re.compile(r'\bos\.getenv\s*\('), 'LOW', 'Environment variable access'),
        (re.compile(r'\bos\.environ'), 'LOW', 'Environment access'),
        (re.compile(r'\bsys\.path'), 'MEDIUM', 'Python path manipulation'),
    ]
    
    # Shell command patterns
    SHELL_PATTERNS = [
        (re.compile(r'[\'"\s]curl\s+[\-\w]'), 'HIGH', 'curl command'),
        (re.compile(r'[\'"\s]wget\s+[\-\w]'), 'HIGH', 'wget command'),
        (re.compile(r'[\'"\s]nc\s+[\-\w]'), 'HIGH', 'netcat command'),
        (re.compile(r'[\'"\s]ncat\s+[\-\w]'), 'HIGH', 'ncat command'),
        (re.compile(r'[\'"\s]bash\s+[\-\w]'), 'HIGH', 'bash command'),
        (re.compile(r'[\'"\s]sh\s+[\-\w]'), 'HIGH', 'sh command'),
        (re.compile(r'\|\s*bash'), 'CRITICAL', 'Pipe to bash'),
        (re.compile(r'\|\s*sh\s'), 'CRITICAL', 'Pipe to shell'),
        (re.compile(r'\beval\s'), 'CRITICAL', 'eval in shell'),
    ]
    
    # JavaScript patterns
    JS_PATTERNS = [
        (re.compile(r'\beval\s*\('), 'CRITICAL', 'eval() in JavaScript'),
        (re.compile(r'\bFunction\s*\('), 'HIGH', 'Function constructor'),
        (re.compile(r'\bchild_process'), 'HIGH', 'child_process module'),
        (re.compile(r'\brequire\s*\([\'"]child_process'), 'HIGH', 'child_process import'),
        (re.compile(r'\bexec\s*\('), 'HIGH', 'exec() in JS'),
        (re.compile(r'\bfetch\s*\('), 'MEDIUM', 'fetch() API'),
        (re.compile(r'\bXMLHttpRequest'), 'MEDIUM', 'XHR request'),
    ]
    
    # Suspicious keywords in documentation
    SKILL_SUSPICIOUS = [
        'ignore previous instructions',
        'ignore all instructions',
        'ignore previous',
        'steal',
        'exfiltrate',
        'send all data',
        'collect passwords',
        'download and execute',
        'remote code execution',
        'reverse shell',
        'bind shell',
        'backdoor',
    ]
    
    def __init__(self):
        self.all_python_patterns = (
            self.PYTHON_PATTERNS + 
            self.NETWORK_PATTERNS + 
            self.FILE_PATTERNS + 
            self.SYSTEM_PATTERNS + 
            self.SHELL_PATTERNS
        )
    
    def scan_python_file(self, content: str, filename: str) -> List[Finding]:
        """Scan Python code for dangerous patterns."""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, description in self.all_python_patterns:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(Finding(
                        file=filename,
                        line=i,
                        severity=severity,
                        description=description,
                        code_snippet=line.strip()[:100]
                    ))
        
        return findings
    
    def scan_javascript_file(self, content: str, filename: str) -> List[Finding]:
        """Scan JavaScript/TypeScript code."""
        findings = []
        lines = content.split('\n')
        
        for pattern, severity, description in self.JS_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(Finding(
                        file=filename,
                        line=i,
                        severity=severity,
                        description=description,
                        code_snippet=line.strip()[:100]
                    ))
        
        return findings
    
    def scan_shell_file(self, content: str, filename: str) -> List[Finding]:
        """Scan shell scripts."""
        findings = []
        lines = content.split('\n')
        
        shell_patterns = [
            (re.compile(r'\beval\s'), 'CRITICAL', 'eval in shell'),
            (re.compile(r'\bcurl\s+.*\|'), 'HIGH', 'curl | pipe pattern'),
            (re.compile(r'\bwget\s+.*\|'), 'HIGH', 'wget | pipe pattern'),
            (re.compile(r'\brm\s+-rf\s+/'), 'CRITICAL', 'rm -rf /'),
            (re.compile(r'\bmkfs\b'), 'CRITICAL', 'filesystem format'),
            (re.compile(r'\bdd\s+if='), 'HIGH', 'dd command'),
        ]
        
        for pattern, severity, description in shell_patterns:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(Finding(
                        file=filename,
                        line=i,
                        severity=severity,
                        description=description,
                        code_snippet=line.strip()[:100]
                    ))
        
        return findings
    
    def scan_skill_md(self, content: str, filename: str) -> List[Finding]:
        """Scan SKILL.md documentation for suspicious content."""
        findings = []
        content_lower = content.lower()
        
        for keyword in self.SKILL_SUSPICIOUS:
            if keyword in content_lower:
                findings.append(Finding(
                    file=filename,
                    line=1,
                    severity='HIGH',
                    description=f'Suspicious phrase: "{keyword}"',
                    code_snippet=''
                ))
        
        return findings
    
    def scan_file(self, filepath: Path, relative_to: Path) -> List[Finding]:
        """Scan any file based on its type."""
        findings = []
        rel_path = filepath.relative_to(relative_to)
        
        try:
            # Skip binary files
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:
                    return findings
            
            # Read as text
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return findings
        
        # Skip very large files
        if len(content) > 10 * 1024 * 1024:  # 10MB
            return findings
        
        # Route to appropriate scanner
        if filepath.name == 'SKILL.md':
            findings.extend(self.scan_skill_md(content, str(rel_path)))
        elif filepath.suffix == '.py':
            findings.extend(self.scan_python_file(content, str(rel_path)))
        elif filepath.suffix in ['.js', '.ts', '.jsx', '.tsx']:
            findings.extend(self.scan_javascript_file(content, str(rel_path)))
        elif filepath.suffix in ['.sh', '.bash']:
            findings.extend(self.scan_shell_file(content, str(rel_path)))
        
        return findings
    
    def determine_status(self, findings: List[Finding]) -> str:
        """Determine overall threat level."""
        if not findings:
            return 'SAFE'
        
        critical = len([f for f in findings if f.severity == 'CRITICAL'])
        high = len([f for f in findings if f.severity == 'HIGH'])
        
        if critical >= 1 or high >= 2:
            return 'DANGEROUS'
        elif high == 1 or len(findings) > 0:
            return 'SUSPICIOUS'
        
        return 'SAFE'
    
    def scan_skill(self, skill_dir: Path) -> dict:
        """
        Scan a complete skill directory.
        
        Args:
            skill_dir: Path to skill directory
            
        Returns:
            Scan result dictionary
        """
        if not skill_dir.exists():
            return {
                'skill': skill_dir.name,
                'status': 'ERROR',
                'findings': [],
                'error': 'Directory not found'
            }
        
        all_findings = []
        files_scanned = 0
        
        # Scan all files
        for filepath in skill_dir.rglob('*'):
            if filepath.is_file():
                findings = self.scan_file(filepath, skill_dir)
                all_findings.extend(findings)
                files_scanned += 1
        
        status = self.determine_status(all_findings)
        
        return {
            'skill': skill_dir.name,
            'status': status,
            'findings': [f.to_dict() for f in all_findings],
            'files_scanned': files_scanned,
            'scanned_at': datetime.utcnow().isoformat()
        }

def generate_report(results: List[dict], output_dir: Path):
    """Generate scan reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Summary statistics
    threats = [r for r in results if r['status'] in ['DANGEROUS', 'SUSPICIOUS']]
    dangerous = [r for r in threats if r['status'] == 'DANGEROUS']
    suspicious = [r for r in threats if r['status'] == 'SUSPICIOUS']
    
    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'scanner_version': __version__,
        'stats': {
            'total_scanned': len(results),
            'threats_found': len(threats),
            'dangerous': len(dangerous),
            'suspicious': len(suspicious)
        },
        'dangerous_skills': dangerous,
        'suspicious_skills': suspicious
    }
    
    # JSON report
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    json_file = output_dir / f'security-report-{timestamp}.json'
    with open(json_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Text report
    summary_file = output_dir / 'latest-security-report.txt'
    with open(summary_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("SKILL SECURITY SCAN REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Generated: {report['generated_at']}\n")
        f.write(f"Scanner Version: {report['scanner_version']}\n")
        f.write(f"Total Scanned: {report['stats']['total_scanned']}\n")
        f.write(f"Threats Found: {report['stats']['threats_found']}\n")
        f.write(f"  - DANGEROUS: {report['stats']['dangerous']}\n")
        f.write(f"  - SUSPICIOUS: {report['stats']['suspicious']}\n\n")
        
        if dangerous:
            f.write("🚨 DANGEROUS SKILLS:\n")
            f.write("-" * 70 + "\n")
            for skill in dangerous:
                f.write(f"\n{skill['skill']}\n")
                for finding in skill['findings'][:5]:
                    f.write(f"  [{finding['severity']}] {finding['file']}:{finding['line']}\n")
                    f.write(f"    {finding['description']}\n")
        
        if suspicious:
            f.write("\n\n⚠️  SUSPICIOUS SKILLS:\n")
            f.write("-" * 70 + "\n")
            for skill in suspicious:
                f.write(f"\n{skill['skill']} - {len(skill['findings'])} findings\n")
                for finding in skill['findings'][:3]:
                    f.write(f"  [{finding['severity']}] {finding['description']}\n")
    
    return json_file, summary_file

def main():
    parser = argparse.ArgumentParser(
        description='Skill Scanner - Security scanner for AI agent skills',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single skill
  %(prog)s /path/to/skill-name/
  
  # Scan directory of skills
  %(prog)s /path/to/skills/
  
  # Scan with custom output
  %(prog)s --output ./reports/ /path/to/skills/
  
  # Scan and generate report only
  %(prog)s --report-only /path/to/skills/
        """
    )
    
    parser.add_argument('path', help='Path to skill directory or parent directory')
    parser.add_argument('-o', '--output', default='./reports', help='Output directory for reports')
    parser.add_argument('--report-only', action='store_true', help='Generate report only, no console output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    target_path = Path(args.path)
    output_path = Path(args.output)
    
    if not target_path.exists():
        print(f"❌ Path not found: {target_path}")
        sys.exit(1)
    
    scanner = SkillScanner()
    results = []
    
    # Determine if single skill or directory of skills
    if (target_path / "SKILL.md").exists():
        # Single skill
        if not args.report_only:
            print(f"🔍 Scanning: {target_path.name}")
        
        result = scanner.scan_skill(target_path)
        results.append(result)
        
        if not args.report_only:
            if result['status'] == 'DANGEROUS':
                print(f"  🚨 DANGEROUS - {len(result['findings'])} findings")
                for f in result['findings'][:3]:
                    print(f"     [{f['severity']}] {f['description']}")
            elif result['status'] == 'SUSPICIOUS':
                print(f"  ⚠️  SUSPICIOUS - {len(result['findings'])} findings")
            else:
                print(f"  ✅ SAFE ({result['files_scanned']} files)")
    else:
        # Directory of skills
        skill_dirs = [d for d in target_path.iterdir() if d.is_dir() and (d / "SKILL.md").exists()]
        
        if not skill_dirs:
            print(f"❌ No skills found in {target_path}")
            sys.exit(1)
        
        if not args.report_only:
            print(f"🔍 Found {len(skill_dirs)} skills to scan\n")
        
        for i, skill_dir in enumerate(skill_dirs, 1):
            if not args.report_only:
                print(f"[{i}/{len(skill_dirs)}] {skill_dir.name}")
            
            result = scanner.scan_skill(skill_dir)
            results.append(result)
            
            if not args.report_only:
                if result['status'] == 'DANGEROUS':
                    print(f"  🚨 DANGEROUS")
                elif result['status'] == 'SUSPICIOUS':
                    print(f"  ⚠️  SUSPICIOUS")
                else:
                    print(f"  ✅ SAFE")
    
    # Generate reports
    json_file, summary_file = generate_report(results, output_path)
    
    if not args.report_only:
        print(f"\n📊 Reports generated:")
        print(f"   JSON: {json_file}")
        print(f"   Text: {summary_file}")
        
        # Summary
        threats = [r for r in results if r['status'] in ['DANGEROUS', 'SUSPICIOUS']]
        print(f"\n{'='*70}")
        print(f"SCAN COMPLETE")
        print(f"{'='*70}")
        print(f"Total: {len(results)}")
        print(f"Threats: {len(threats)}")
        if threats:
            print(f"  🚨 Dangerous: {len([r for r in threats if r['status'] == 'DANGEROUS'])}")
            print(f"  ⚠️  Suspicious: {len([r for r in threats if r['status'] == 'SUSPICIOUS'])}")

if __name__ == "__main__":
    main()