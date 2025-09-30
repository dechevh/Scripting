# Certificate Expiry Checker

## Overview
Python script that checks SSL/TLS certificate expiry for a list of hosts.  
It prints a table with status, days left, and expiry date.  
- Handles errors (shows `ERROR` instead of crashing).  
- Supports thresholds (`warn_days`, `crit_days`) from `config.yaml`.  
- Exit codes:  
  - 0 = all OK  
  - 1 = at least one WARN  
  - 2 = at least one CRIT  
  - 3 = error(s) occurred  

## Usage

### 1. Install
```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run
```bash
python cert_checker.py
```

By default, it loads `config.yaml` from the same directory.  
To override:
```bash
CONFIG=my_config.yaml python cert_checker.py
```

### 3. Example output
```
HOST                      PORT  STATUS DAYS  EXPIRES(UTC or ERROR)
-------------------------------------------------------------------
google.com                443   OK       72  2025-12-01T12:00:00+00:00
expired.badssl.com        443   CRIT      -1  2023-10-30T12:00:00+00:00
does-not-exist.example    443   ERROR  ----   [Errno -2] Name or service not known
```

## Config file example (`config.yaml`)
```yaml
warn_days: 30
crit_days: 7
sites:
  - host: google.com
    port: 443
  - host: expired.badssl.com
    port: 443
    sni: expired.badssl.com   # optional
  - host: does-not-exist.example
    port: 443
```

## Next steps
- Add Slack/Email alerts for WARN/CRIT.
- Package with Docker for portable runs.
- Schedule with cron or AWS Lambda for automation.