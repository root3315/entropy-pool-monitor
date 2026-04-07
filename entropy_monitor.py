#!/usr/bin/env python3
"""
Entropy Pool Monitor - Monitors system entropy levels for cryptographic operations.
"""

import os
import sys
import time
import signal
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

from config import load_config, DEFAULT_CONFIG, CONFIG_SEARCH_PATHS

ENTROPY_AVAIL_PATH = "/proc/sys/kernel/random/entropy_avail"
ENTROPY_POOL_SIZE_PATH = "/proc/sys/kernel/random/poolsize"
URANDOM_PATH = "/dev/urandom"

READ_RETRIES = 3
READ_RETRY_DELAY = 0.1
FALLBACK_ENTROPY_ESTIMATE = 256


class EntropyMonitor:
    def __init__(self, threshold=DEFAULT_CONFIG["threshold"],
                 interval=DEFAULT_CONFIG["interval"],
                 max_history=DEFAULT_CONFIG["max_history"],
                 log_file=None, alert_command=None):
        self.threshold = threshold
        self.interval = interval
        self.max_history = max_history
        self.log_file = log_file
        self.alert_command = alert_command
        self.running = True
        self.alerts_triggered = 0
        self.history = []

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.running = False

    def read_entropy_avail(self):
        last_error = None
        for attempt in range(READ_RETRIES):
            try:
                with open(ENTROPY_AVAIL_PATH, 'r') as f:
                    return int(f.read().strip())
            except FileNotFoundError:
                last_error = -1
                break
            except PermissionError:
                last_error = -2
                break
            except ValueError:
                last_error = -3
                break
            except (IOError, OSError):
                last_error = -4
                if attempt < READ_RETRIES - 1:
                    time.sleep(READ_RETRY_DELAY * (2 ** attempt))
                continue

        return last_error

    def read_entropy_fallback(self):
        """
        Attempt to estimate entropy when /proc/sys/kernel/random/entropy_avail
        is unavailable. Tries reading from /dev/urandom as a fallback indicator.
        Returns estimated entropy bits or negative error code.
        """
        if not os.path.exists(URANDOM_PATH):
            return -5

        try:
            with open(URANDOM_PATH, 'rb') as f:
                sample = f.read(32)
                if len(sample) == 32:
                    return FALLBACK_ENTROPY_ESTIMATE
                return -6
        except (IOError, OSError):
            return -7

    def read_pool_size(self):
        last_error = None
        for attempt in range(READ_RETRIES):
            try:
                with open(ENTROPY_POOL_SIZE_PATH, 'r') as f:
                    return int(f.read().strip())
            except FileNotFoundError:
                return 4096
            except PermissionError:
                return 4096
            except ValueError:
                if attempt < READ_RETRIES - 1:
                    time.sleep(READ_RETRY_DELAY * (2 ** attempt))
                continue
            except (IOError, OSError):
                if attempt < READ_RETRIES - 1:
                    time.sleep(READ_RETRY_DELAY * (2 ** attempt))
                continue

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

        if self.log_file:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(log_line + "\n")
            except IOError:
                pass

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

        if self.alert_command:
            try:
                subprocess.run(
                    self.alert_command,
                    shell=True,
                    capture_output=True,
                    timeout=5
                )
            except (subprocess.SubprocessError, OSError):
                pass

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
        using_fallback = False

        if available < 0:
            fallback = self.read_entropy_fallback()
            if fallback > 0:
                available = fallback
                using_fallback = True
            else:
                error_messages = {
                    -1: "ERROR: Cannot access entropy_avail - file not found",
                    -2: "ERROR: Permission denied reading entropy_avail",
                    -3: "ERROR: Invalid value in entropy_avail",
                    -4: "ERROR: Failed to read entropy_avail after retries",
                    -5: "ERROR: No fallback entropy source available (/dev/urandom missing)",
                    -6: "ERROR: Failed to read from /dev/urandom",
                    -7: "ERROR: I/O error reading /dev/urandom",
                }
                print(error_messages.get(available, "ERROR: Unknown error reading entropy"))
                return False

        percentage = self.get_entropy_percentage(available, pool_size)
        self.log_status(available, pool_size, percentage)

        if using_fallback:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"  ⚠ Using fallback entropy estimate ({FALLBACK_ENTROPY_ESTIMATE} bits)")

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
        if self.log_file:
            print(f"Log file: {self.log_file}")
        if self.alert_command:
            print(f"Alert command: {self.alert_command}")
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
        using_fallback = False

        if available < 0:
            fallback = self.read_entropy_fallback()
            if fallback > 0:
                available = fallback
                using_fallback = True
            else:
                print(f"Error reading entropy: code {available}")
                return 1

        percentage = self.get_entropy_percentage(available, pool_size)

        print(f"Available entropy: {available} bits")
        print(f"Pool size: {pool_size} bits")
        print(f"Usage: {percentage:.1f}%")
        if using_fallback:
            print(f"Note: Using fallback entropy estimate")

        if available < self.threshold:
            print(f"Status: WARNING - Below threshold ({self.threshold} bits)")
            return 1
        else:
            print(f"Status: OK")
            return 0


def main():
    config = load_config()

    parser = argparse.ArgumentParser(
        description="Monitor system entropy pool levels for cryptographic operations"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=config.get("threshold", DEFAULT_CONFIG["threshold"]),
        help=f"Alert threshold in bits (default: {config.get('threshold', DEFAULT_CONFIG['threshold'])})"
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=config.get("interval", DEFAULT_CONFIG["interval"]),
        help=f"Monitoring interval in seconds (default: {config.get('interval', DEFAULT_CONFIG['interval'])})"
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
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file (default: search standard locations)"
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate a sample configuration file and exit"
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show current configuration and exit"
    )

    args = parser.parse_args()

    if args.generate_config:
        from config import generate_sample_config, save_config
        sample = generate_sample_config()
        if args.config:
            save_path = save_config(sample, args.config)
        else:
            save_path = save_config(sample)
        print(f"Configuration written to: {save_path}")
        sys.exit(0)

    if args.show_config:
        if args.config:
            config = load_config(args.config)
        print("Current configuration:")
        for key, value in config.items():
            print(f"  {key}: {value}")
        sys.exit(0)

    if args.config:
        config = load_config(args.config)

    threshold = args.threshold
    interval = args.interval
    max_history = config.get("max_history", DEFAULT_CONFIG["max_history"])
    log_file = config.get("log_file")
    alert_command = config.get("alert_command")

    monitor = EntropyMonitor(
        threshold=threshold,
        interval=interval,
        max_history=max_history,
        log_file=log_file,
        alert_command=alert_command
    )

    if args.check or args.json:
        available = monitor.read_entropy_avail()
        pool_size = monitor.read_pool_size()
        using_fallback = False

        if available < 0:
            fallback = monitor.read_entropy_fallback()
            if fallback > 0:
                available = fallback
                using_fallback = True
            else:
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
                "threshold": threshold,
                "status": "ok" if available >= threshold else "low"
            }
            if using_fallback:
                output["fallback"] = True
            print(json.dumps(output, indent=2))
        else:
            print(f"Available entropy: {available} bits")
            print(f"Pool size: {pool_size} bits")
            print(f"Usage: {percentage:.1f}%")
            if using_fallback:
                print(f"Note: Using fallback entropy estimate")
            if available < threshold:
                print(f"Status: WARNING - Below threshold ({threshold} bits)")
                sys.exit(1)
            else:
                print("Status: OK")
    else:
        monitor.run_continuous()


if __name__ == "__main__":
    main()
