#!/usr/bin/env python3
"""
Entropy Pool Monitor - Monitors system entropy levels for cryptographic operations.
"""

import os
import sys
import time
import signal
import argparse
from datetime import datetime
from pathlib import Path

ENTROPY_AVAIL_PATH = "/proc/sys/kernel/random/entropy_avail"
ENTROPY_POOL_SIZE_PATH = "/proc/sys/kernel/random/poolsize"
DEFAULT_THRESHOLD = 512
DEFAULT_INTERVAL = 2.0


class EntropyMonitor:
    def __init__(self, threshold=DEFAULT_THRESHOLD, interval=DEFAULT_INTERVAL):
        self.threshold = threshold
        self.interval = interval
        self.running = True
        self.alerts_triggered = 0
        self.history = []
        self.max_history = 100

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.running = False

    def read_entropy_avail(self):
        try:
            with open(ENTROPY_AVAIL_PATH, 'r') as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return -1
        except PermissionError:
            return -2
        except ValueError:
            return -3

    def read_pool_size(self):
        try:
            with open(ENTROPY_POOL_SIZE_PATH, 'r') as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return 4096
        except PermissionError:
            return 4096

    def get_entropy_percentage(self, available, pool_size):
        if pool_size <= 0:
            return 0.0
        return (available / pool_size) * 100

    def log_status(self, available, pool_size, percentage):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "OK" if available >= self.threshold else "LOW"
        bar_length = 30
        filled = int(bar_length * percentage / 100)
        bar = "█" * filled + "░" * (bar_length - filled)

        log_line = f"[{timestamp}] Entropy: {available:4d}/{pool_size} [{bar}] {percentage:5.1f}% | Status: {status}"
        print(log_line)

        self.history.append({
            "timestamp": timestamp,
            "available": available,
            "pool_size": pool_size,
            "percentage": percentage,
            "status": status
        })

        if len(self.history) > self.max_history:
            self.history.pop(0)

    def trigger_alert(self, available):
        self.alerts_triggered += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"\n⚠️  ALERT [{timestamp}]: Entropy critically low! ({available} bits)\n"
        alert_msg += "   Cryptographic operations may be slow or insecure.\n"
        alert_msg += "   Consider installing rng-tools or haveged.\n"
        print(alert_msg, file=sys.stderr)

    def check_entropy_sources(self):
        sources = []
        rng_paths = [
            "/dev/random",
            "/dev/urandom",
            "/dev/hwrng"
        ]

        for path in rng_paths:
            if os.path.exists(path):
                stat_info = os.stat(path)
                sources.append({
                    "path": path,
                    "exists": True,
                    "mode": oct(stat_info.st_mode)[-3:]
                })
            else:
                sources.append({
                    "path": path,
                    "exists": False,
                    "mode": None
                })

        return sources

    def run_once(self):
        available = self.read_entropy_avail()
        pool_size = self.read_pool_size()

        if available < 0:
            error_messages = {
                -1: "ERROR: Cannot access entropy_avail - file not found",
                -2: "ERROR: Permission denied reading entropy_avail",
                -3: "ERROR: Invalid value in entropy_avail"
            }
            print(error_messages.get(available, "ERROR: Unknown error reading entropy"))
            return False

        percentage = self.get_entropy_percentage(available, pool_size)
        self.log_status(available, pool_size, percentage)

        if available < self.threshold:
            self.trigger_alert(available)

        return True

    def run_continuous(self):
        print("=" * 70)
        print("Entropy Pool Monitor")
        print("=" * 70)
        print(f"Threshold: {self.threshold} bits")
        print(f"Interval: {self.interval}s")
        print(f"Monitoring /proc/sys/kernel/random/entropy_avail")
        print("=" * 70)
        print()

        sources = self.check_entropy_sources()
        print("Available entropy sources:")
        for src in sources:
            status = "✓" if src["exists"] else "✗"
            mode_info = f" (mode: {src['mode']})" if src["mode"] else ""
            print(f"  {status} {src['path']}{mode_info}")
        print()
        print("Starting monitoring... (Press Ctrl+C to stop)")
        print("-" * 70)

        try:
            while self.running:
                success = self.run_once()
                if not success:
                    break

                for _ in range(int(self.interval * 10)):
                    if not self.running:
                        break
                    time.sleep(0.1)
        except KeyboardInterrupt:
            pass

        print("-" * 70)
        print(f"Monitoring stopped. Total alerts triggered: {self.alerts_triggered}")

        if self.history:
            avg_entropy = sum(h["available"] for h in self.history) / len(self.history)
            min_entropy = min(h["available"] for h in self.history)
            max_entropy = max(h["available"] for h in self.history)
            print(f"Average entropy: {avg_entropy:.1f} bits")
            print(f"Min entropy: {min_entropy} bits")
            print(f"Max entropy: {max_entropy} bits")

    def run_check(self):
        available = self.read_entropy_avail()
        pool_size = self.read_pool_size()

        if available < 0:
            print(f"Error reading entropy: code {available}")
            return 1

        percentage = self.get_entropy_percentage(available, pool_size)

        print(f"Available entropy: {available} bits")
        print(f"Pool size: {pool_size} bits")
        print(f"Usage: {percentage:.1f}%")

        if available < self.threshold:
            print(f"Status: WARNING - Below threshold ({self.threshold} bits)")
            return 1
        else:
            print(f"Status: OK")
            return 0


def main():
    parser = argparse.ArgumentParser(
        description="Monitor system entropy pool levels for cryptographic operations"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Alert threshold in bits (default: {DEFAULT_THRESHOLD})"
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Monitoring interval in seconds (default: {DEFAULT_INTERVAL})"
    )
    parser.add_argument(
        "-c", "--check",
        action="store_true",
        help="Single check mode (no continuous monitoring)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output single check as JSON"
    )

    args = parser.parse_args()

    monitor = EntropyMonitor(threshold=args.threshold, interval=args.interval)

    if args.check or args.json:
        available = monitor.read_entropy_avail()
        pool_size = monitor.read_pool_size()

        if available < 0:
            if args.json:
                print('{"error": "cannot_read_entropy", "code": ' + str(available) + '}')
            else:
                print(f"Error reading entropy: code {available}")
            sys.exit(1)

        percentage = monitor.get_entropy_percentage(available, pool_size)

        if args.json:
            import json
            output = {
                "available": available,
                "pool_size": pool_size,
                "percentage": round(percentage, 2),
                "threshold": args.threshold,
                "status": "ok" if available >= args.threshold else "low"
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Available entropy: {available} bits")
            print(f"Pool size: {pool_size} bits")
            print(f"Usage: {percentage:.1f}%")
            if available < args.threshold:
                print(f"Status: WARNING - Below threshold ({args.threshold} bits)")
                sys.exit(1)
            else:
                print("Status: OK")
    else:
        monitor.run_continuous()


if __name__ == "__main__":
    main()
