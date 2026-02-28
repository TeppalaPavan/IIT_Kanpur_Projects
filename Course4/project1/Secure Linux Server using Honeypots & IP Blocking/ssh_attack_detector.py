#!/usr/bin/env python3

import re
import time
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5   # number of failed attempts to flag
TIME_WINDOW = 300  # seconds (5 minutes)

# regex to extract IP from “Failed password” lines
failed_pattern = re.compile(
    r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
)

def follow_log(file):
    file.seek(0, 2)  # go to end
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def monitor_ssh_attacks():
    print("[*] Starting SSH attack detector...")
    attempt_log = defaultdict(list)

    with open(LOG_FILE, "r") as f:
        log_lines = follow_log(f)

        for line in log_lines:
            match = failed_pattern.search(line)
            if match:
                ip = match.group(1)
                curr_time = time.time()
                attempt_log[ip].append(curr_time)
                print(f"[!] Failed SSH attempt from {ip}")

                # filter recent attempts
                recent = [
                    t for t in attempt_log[ip]
                    if curr_time - t <= TIME_WINDOW
                ]
                attempt_log[ip] = recent

                if len(recent) >= THRESHOLD:
                    print(
                        f"[!!] Brute force suspected from {ip}: "
                        f"{len(recent)} fails in {TIME_WINDOW//60} minutes"
                    )

if __name__ == "__main__":
    try:
        monitor_ssh_attacks()
    except KeyboardInterrupt:
        print("\n[!] Stopped SSH attack detector.")
