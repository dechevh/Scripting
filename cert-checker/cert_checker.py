import socket
import ssl
import datetime
import os
import sys
import yaml

# Load YAML config file with list of sites and saves it as Python dic
def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# Get peer certificate expiry (notAfter) as UTC datetime.
def get_cert_expiry(host, port=443, server_hostname=None):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname or host) as ssock:
            cert = ssock.getpeercert()
            not_after = cert.get("notAfter")
            if not_after is None:
                raise ValueError("Certificate has no notAfter")
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return exp.replace(tzinfo=datetime.timezone.utc)

def days_until(expiry_dt):
    now = datetime.datetime.now(datetime.timezone.utc)
    return int((expiry_dt - now).total_seconds() // 86400)

# Check single host and return printable line (do not raise/crash).
def check_host(host, port=443, sni=None, warn_days=30, crit_days=7):
    try:
        exp = get_cert_expiry(host, port, sni)
        dleft = days_until(exp)

        # Default status
        status = "OK"
        exit_code = 0

        if dleft <= crit_days:
            status = "CRIT"
            exit_code = 2
        elif dleft <= warn_days:
            status = "WARN"
            exit_code = 1

        line = f"{host:<25} {port:<5} {status:<5}  {dleft:>5}  {exp.isoformat()}"
        return line, exit_code

    except Exception as e:
        line = f"{host:<25} {port:<5} ERROR  ----   {e}"
        return line, 3

def main():
    # Allow overriding config file via ENV var CONFIG; default to ./config.yaml
    cfg_path = os.environ.get("CONFIG", "config.yaml")
    cfg = load_config(cfg_path)

    warn_days = cfg.get("warn_days", 30)
    crit_days = cfg.get("crit_days", 7)
    sites = cfg.get("sites", [])

    print("HOST                      PORT  STATUS DAYS  EXPIRES(UTC or ERROR)")
    print("-" * 75)

    exit_code = 0
    for t in sites:
        host = t.get("host")
        port = int(t.get("port", 443))
        sni  = t.get("sni")
        line, code = check_host(host, port, sni, warn_days, crit_days)
        print(line)
        # escalate exit_code if needed
        if code > exit_code:
            exit_code = code

    sys.exit(exit_code)

if __name__ == "__main__":
    main()