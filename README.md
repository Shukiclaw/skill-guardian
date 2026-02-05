# Skill Guardian - ClawdHub Security Scanner

Mass security scanner for ClawdHub skills. Scans skills in batches without executing any code.

## Features

- 🔒 **Safe**: Only downloads SKILL.md (documentation), never executes code
- 📦 **Batch Processing**: Scans skills in configurable batches
- 📊 **Queue Management**: Maintains persistent queue of skills to scan
- 🚨 **Threat Detection**: Identifies dangerous patterns in skill documentation
- 📈 **Reports**: Generates detailed JSON and text reports
- 🔄 **Resumable**: Can pause and resume scanning

## Quick Start

```bash
# Collect all skills and add to queue
python3 batch_scanner.py --collect-only

# Scan one batch
python3 batch_scanner.py --once

# Continuous scanning
python3 batch_scanner.py

# Generate report
python3 batch_scanner.py --report
```

## How It Works

1. **Collection**: Searches ClawdHub for all available skills
2. **Queue**: Maintains a persistent queue in `~/.openclaw/clawdhub-scan-db.json`
3. **Batch Scan**: Processes skills in small batches (default: 5)
4. **Analysis**: Scans SKILL.md for suspicious patterns
5. **Report**: Saves results to `~/.openclaw/reports/`

## Detection Patterns

### Critical (DANGEROUS)
- `exec()`, `eval()`, `__import__()`
- `shell=True`
- Email sending capabilities

### High (DANGEROUS)
- `subprocess` usage
- `os.system()` calls
- Network tools (curl, wget, netcat)

### Medium (SUSPICIOUS)
- HTTP requests
- Socket usage
- File writing

## Database Location

```
~/.openclaw/clawdhub-scan-db.json
```

Contains:
- `scanned_skills`: Results of all scanned skills
- `queue`: Skills waiting to be scanned
- `threats`: List of suspicious/dangerous skills
- `stats`: Scanning statistics

## Reports

Generated in `~/.openclaw/reports/`:
- `report-YYYYMMDD-HHMMSS.json`: Full JSON report
- `latest-summary.txt`: Human-readable summary

## Safety

This scanner is designed to be safe:
- ✅ Never executes skill code
- ✅ Only downloads SKILL.md (markdown documentation)
- ✅ Cleans up immediately after each scan
- ✅ Uses timeouts to prevent hanging

## Requirements

- Python 3.8+
- `clawdhub` CLI installed
- Internet connection to ClawdHub

## License

MIT