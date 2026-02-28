#!/usr/bin/env python3

import re
import subprocess
import argparse
from collections import Counter
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
SSH_PORT = "2222"

FAILED_REGEX = re.compile(
    r"Failed password.*from (\d+\.\d+\.\d+\.\d+).*port"
)

def tail_log():
    """Real-time failed SSH monitoring"""
    print(f"[+] Monitoring failed SSH attempts on port {SSH_PORT}")
    try:
        with open(LOG_FILE, "r") as f:
            f.seek(0, 2)  # go to end of file
            while True:
                line = f.readline()
                if not line:
                    continue
                if "Failed password" in line and f"port {SSH_PORT}" in line:
                    ip = FAILED_REGEX.search(line)
                    if ip:
                        print(f"[ALERT] Failed SSH login from {ip.group(1)}")
    except KeyboardInterrupt:
        print("\n[!] Stopped monitoring")


def parse_daily():
    """Generate daily attack report"""
    ips = []

    with open(LOG_FILE, "r") as f:
        for line in f:
            if "Failed password" in line and f"port {SSH_PORT}" in line:
                match = FAILED_REGEX.search(line)
                if match:
                    ips.append(match.group(1))

    if not ips:
        print("[+] No failed SSH attempts found today.")
        return

    ip_count = Counter(ips)

    print("\n=== Daily SSH Attack Report ===")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
    print(f"Total Failed Attempts: {len(ips)}\n")

    for ip, count in ip_count.items():
        country = whois_country(ip)
        print(f"IP: {ip}")
        print(f"Attempts: {count}")
        print(f"Country: {country}")
        print("-" * 40)


def whois_country(ip):
    """Extract country info from WHOIS"""
    try:
        result = subprocess.check_output(
            ["whois", ip],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10
        )
        for line in result.splitlines():
            if re.search(r"country", line, re.IGNORECASE):
                return line.split(":")[-1].strip()
    except Exception:
        return "Unknown"
    return "Unknown"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Attack Monitoring Tool")
    parser.add_argument("--realtime", action="store_true", help="Real-time SSH monitoring")
    parser.add_argument("--daily", action="store_true", help="Daily SSH attack report")

    args = parser.parse_args()

    if args.realtime:
        tail_log()
    elif args.daily:
        parse_daily()
    else:
        parser.print_help()
