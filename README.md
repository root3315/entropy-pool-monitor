# entropy-pool-monitor

Quick tool to keep an eye on your system's entropy pool. If you're doing crypto stuff and entropy runs dry, things get slow (or worse, insecure). This watches that for you.

## Why this exists

Linux pulls entropy from hardware events - keyboard presses, mouse moves, disk I/O, that kind of thing. When you need random numbers for encryption keys, TLS handshakes, or anything crypto-related, the system dips into this entropy pool.

If the pool empties out:
- `/dev/random` blocks until more entropy shows up
- Your app hangs waiting for keys
- Bad things happen

This monitor just watches `/proc/sys/kernel/random/entropy_avail` and yells when it drops too low.

## Quick start

```bash
# Just check current entropy
python3 entropy_monitor.py --check

# Continuous monitoring (default 2s interval)
python3 entropy_monitor.py

# Custom threshold and interval
python3 entropy_monitor.py -t 256 -i 1.0

# JSON output for scripting
python3 entropy_monitor.py --check --json
```

## Configuration file

The monitor can read settings from a JSON configuration file. It searches for config in these locations (first match wins):

1. `.entropy_monitor.json` (current directory)
2. `~/.config/entropy_monitor/config.json` (user config)
3. `/etc/entropy_monitor/config.json` (system config)

### Configuration options

```json
{
  "threshold": 512,
  "interval": 2.0,
  "max_history": 100,
  "log_file": "/var/log/entropy_monitor.log",
  "alert_command": "notify-send 'Low Entropy' 'Entropy pool is below threshold'"
}
```

- **threshold**: Alert when entropy drops below this value (bits)
- **interval**: Time between checks in seconds
- **max_history**: Number of readings to keep for session statistics
- **log_file**: Optional path to append log entries
- **alert_command**: Shell command to run when entropy is low

### Config management commands

```bash
# Generate a sample config file
python3 entropy_monitor.py --generate-config

# Generate config to specific location
python3 entropy_monitor.py --generate-config --config /path/to/config.json

# Show current configuration
python3 entropy_monitor.py --show-config

# Use a specific config file
python3 entropy_monitor.py --config /path/to/config.json
```

Command-line arguments override configuration file values.

## What the numbers mean

- **Pool size**: Usually 4096 bits on modern kernels (256 bits on older ones)
- **Available**: How much entropy is actually in the pool right now
- **Threshold**: When to start alerting (default 512 bits)

If you're consistently below 512 bits, you probably need more entropy sources.

## Fixing low entropy

If this tool keeps alerting you, consider:

1. **rng-tools**: Pulls from hardware RNG if your CPU has one
   ```bash
   sudo apt install rng-tools
   sudo systemctl enable rng-tools
   ```

2. **haveged**: Generates entropy from CPU timing variations
   ```bash
   sudo apt install haveged
   sudo systemctl enable haveged
   ```

3. **Check for hardware RNG**:
   ```bash
   ls -la /dev/hwrng
   ```

## Output format

Continuous mode looks like:

```
======================================================================
Entropy Pool Monitor
======================================================================
Threshold: 512 bits
Interval: 2.0s
Monitoring /proc/sys/kernel/random/entropy_avail
======================================================================

Available entropy sources:
  ✓ /dev/random (mode: 666)
  ✓ /dev/urandom (mode: 666)
  ✗ /dev/hwrng

Starting monitoring... (Press Ctrl+C to stop)
----------------------------------------------------------------------
[2026-03-17 14:32:01] Entropy:  847/4096 [█████████░░░░░░░░░░░░░░░░░]  20.7% | Status: OK
[2026-03-17 14:32:03] Entropy:  723/4096 [████████░░░░░░░░░░░░░░░░░░]  17.7% | Status: OK
```

When it drops below threshold, you get an alert to stderr.

## Exit codes

- `0`: All good (or clean exit from monitoring)
- `1`: Entropy below threshold (check mode) or error reading entropy

## Notes

- Needs read access to `/proc/sys/kernel/random/entropy_avail` (usually works without root)
- The visual bar is 30 chars, scaled to pool size
- History keeps last 100 readings for session stats
- Handles SIGINT/SIGTERM gracefully

## License

Do what you want with it.
