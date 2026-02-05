# Skill Scanner 🔒

Universal security scanner for AI agent skills (ClawdHub, etc.)
Performs static analysis without executing any code.

## Features

- ✅ **Universal**: Works with any skill package format
- ✅ **Safe**: Static analysis only - no code execution
- ✅ **Multi-language**: Python, JavaScript, TypeScript, Shell
- ✅ **Comprehensive**: Detects 50+ dangerous patterns
- ✅ **Reporting**: JSON and human-readable reports

## Installation

```bash
git clone https://github.com/Shukiclaw/skill-scanner.git
cd skill-scanner
chmod +x skill_scanner.py
```

## Usage

### Scan Single Skill

```bash
python3 skill_scanner.py /path/to/skill-name/
```

### Scan Directory of Skills

```bash
python3 skill_scanner.py /path/to/skills/
```

### Examples

```bash
# Scan downloaded ClawdHub skills
python3 skill_scanner.py ~/clawdhub-storage/

# Scan with custom output directory
python3 skill_scanner.py -o ./my-reports/ ~/skills/

# Generate report only (quiet mode)
python3 skill_scanner.py --report-only ~/skills/
```

## What Gets Detected

### CRITICAL (Immediate Danger)
- `exec()`, `eval()`, `__import__()` - Dynamic code execution
- `shell=True` - Shell injection risk
- `pty.spawn()` - Pseudo-terminal spawn
- SMTP/email capabilities
- Telnet access

### HIGH (Suspicious)
- `subprocess` usage
- `os.system()`, `os.popen()`
- `child_process` (Node.js)
- Pipe to shell (`| bash`)
- Network tools (curl, wget, netcat)

### MEDIUM (Attention Needed)
- HTTP requests
- Socket usage
- File write operations
- Dynamic imports

### Documentation Checks
- "ignore previous instructions"
- "steal", "exfiltrate", "backdoor"
- "reverse shell", "bind shell"

## Output

Reports are generated in the specified output directory (default: `./reports/`):

- `security-report-YYYYMMDD-HHMMSS.json` - Full JSON report
- `latest-security-report.txt` - Human-readable summary

### Example Report

```
======================================================================
SKILL SECURITY SCAN REPORT
======================================================================

Generated: 2026-02-05T10:00:00
Scanner Version: 1.0.0
Total Scanned: 100
Threats Found: 5
  - DANGEROUS: 2
  - SUSPICIOUS: 3

🚨 DANGEROUS SKILLS:
----------------------------------------------------------------------

malicious-skill
  [CRITICAL] main.py:15 - exec() - dynamic code execution
  [HIGH] main.py:23 - subprocess execution
  [CRITICAL] utils.py:8 - shell=True injection risk

⚠️  SUSPICIOUS SKILLS:
----------------------------------------------------------------------

network-skill - 3 findings
  [MEDIUM] fetch data from remote server
  [MEDIUM] HTTP request to external API
```

## Use with ClawdHub

### 1. Download Skills

Use `clawdhub` CLI to download skills to local storage:

```bash
# Download skills (do this separately)
clawdhub install skill-name --dir ~/clawdhub-storage/
```

### 2. Scan Downloaded Skills

```bash
# Scan all downloaded skills
python3 skill_scanner.py ~/clawdhub-storage/
```

### 3. Review Report

```bash
cat ./reports/latest-security-report.txt
```

## Safety

This scanner is completely safe:

- ✅ **No Execution**: Only reads files, never runs them
- ✅ **Static Analysis**: Pattern matching only
- ✅ **Read-Only**: Never modifies scanned files
- ✅ **Local**: All processing done locally

## Requirements

- Python 3.7+
- No external dependencies (stdlib only)

## Supported File Types

- `.py` - Python
- `.js`, `.ts`, `.jsx`, `.tsx` - JavaScript/TypeScript
- `.sh`, `.bash` - Shell scripts
- `SKILL.md` - Skill documentation

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Author

Created by Shuki 🤖🍺