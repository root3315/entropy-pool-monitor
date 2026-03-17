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
