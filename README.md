# PyMap2

A fast, async TCP port scanner for internal and external network reconnaissance. Built in Python using `asyncio` for high-throughput concurrent scanning with a rich feature set including banner grabbing, reverse DNS, resume support, IPv6, and live pause/resume controls.

**Made by James Ball**

---

## Features

- **Async scanning** — thousands of simultaneous TCP connections via `asyncio`
- **IPv4 & IPv6** — scan CIDR ranges or provide a flat list of IPs
- **Flexible port input** — comma-separated, ranges (`443-445`), or presets (`top20`, `top100`)
- **Banner grabbing** — read service responses from open ports
- **Reverse DNS** — resolve hostnames for open IPs
- **Resume** — pick up an interrupted scan where it left off
- **Shuffle** — randomise scan order to reduce IDS detection risk
- **Closed port logging** — record every result, not just open ports
- **Live pause/resume** — keyboard controls during an active scan
- **Graceful Ctrl+C** — buffers are flushed to CSV before exit
- **CSV output** — structured results with IP, port, status, hostname, banner, and timestamp
- **Audit log** — plain-text log of scan config, flushes, and totals
- **Time-based CSV flushing** — results written to disk on a configurable interval
- **Interactive mode** — guided prompts when run with no arguments

---

## Requirements

- Python 3.8+
- No third-party packages — standard library only

---

## Installation

```bash
git clone https://github.com/yourusername/PyMap2.git
cd PyMap2
```

No install step needed. Run directly with Python.

---

## Usage

### Interactive mode

Run with no arguments to be guided through all options:

```bash
python PyMap2.py
```

### CLI mode

Pass flags directly for scripting and automation:

```bash
python PyMap2.py [OPTIONS]
```

---

## Flags

### Target (pick one)

| Flag | Description |
|------|-------------|
| `-n`, `--network CIDR` | IPv4 or IPv6 CIDR range — e.g. `192.168.1.0/24` or `fd00::/120` |
| `-f`, `--file PATH` | Text file with one IP per line. Blank lines and `#` comments are ignored. |

### Ports

| Flag | Description |
|------|-------------|
| `-p`, `--ports PORTS` | Comma-separated ports or ranges e.g. `22,80,443-445`. Presets: `top20`, `top100`. Default: `22,80,443,9100` |

### Tuning

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--timeout SECS` | `1.0` | TCP connect timeout in seconds |
| `-c`, `--concurrency N` | `5000` | Max simultaneous connections |
| `--flush-interval SECS` | `30` | Write results to CSV every N seconds |

> **Caveat:** Concurrency values above ~10,000 may exhaust OS file descriptors. If you see *"Too many open files"*, lower this value.

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output FILE` | `scan_results.csv` | CSV results file |
| `-l`, `--log FILE` | `scan.log` | Plain-text audit log |

### Optional Features

| Flag | Description | Caveat |
|------|-------------|--------|
| `--banner` | Grab service banners from open ports | Adds latency per open port. Lower `-c` and raise `-t` when using. |
| `--resolve` | Reverse-DNS each open IP for a hostname | Slow on large ranges — avoid on anything larger than a `/24`. |
| `--shuffle` | Randomise scan order | Loads all targets into memory before scanning begins. |
| `--log-closed` | Record closed/filtered ports in the CSV | Massively increases file size on large ranges. A full `/8` scan at 4 ports = ~67M rows. |
| `--resume` | Skip IP:port pairs already in the output CSV | The original output file must be intact and use the same filename. |

---

## Controls During a Scan

| Input | Action |
|-------|--------|
| `p` + Enter | Pause scanning |
| `r` + Enter | Resume scanning |
| `q` + Enter | Save buffered results and quit |
| `Ctrl+C` | Graceful exit — flushes buffer to CSV first |
| `Ctrl+C` twice | Force quit immediately |

---

## Examples

Scan a local subnet for top 20 common ports with banner grabbing and hostname resolution:

```bash
python PyMap2.py -n 192.168.0.0/16 -p top20 --banner --resolve
```

Scan a list of specific IPs, shuffling order, resuming a previous run:

```bash
python PyMap2.py -f targets.txt -p 22,80,443 --shuffle --resume
```

Scan a large internal range quietly to a custom output file:

```bash
python PyMap2.py -n 10.0.0.0/8 -p 80,443 -c 2000 -o web_servers.csv
```

Scan an IPv6 range:

```bash
python PyMap2.py -n fd00::/120 -p top20
```

Full-featured scan with all options:

```bash
python PyMap2.py -n 172.16.0.0/12 -p top100 -t 2.0 -c 3000 \
  --banner --resolve --shuffle --log-closed \
  -o results.csv -l audit.log --flush-interval 60
```

---

## CSV Output Format

| Column | Description |
|--------|-------------|
| `ip` | Target IP address |
| `port` | Target port number |
| `status` | `open` or `closed` (if `--log-closed` is set) |
| `hostname` | Reverse-DNS result (if `--resolve` is set, otherwise blank) |
| `banner` | Service banner (if `--banner` is set, otherwise blank) |
| `timestamp` | UTC timestamp of the result |

Example output:

```
ip,port,status,hostname,banner,timestamp
192.168.1.1,80,open,router.local,HTTP/1.1 200 OK,2026-05-26T10:32:01.123456
192.168.1.5,22,open,web01.internal,SSH-2.0-OpenSSH_8.9,2026-05-26T10:32:02.654321
```

---

## IP File Format

When using `-f`, provide a plain text file with one IP per line:

```
# Web servers
192.168.1.10
192.168.1.11

# Database servers
10.0.0.50
fd00::1
```

---

## Top Port Presets

| Preset | Ports |
|--------|-------|
| `top20` | 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080 |
| `top100` | 100 most commonly scanned TCP ports (see source for full list) |

---

## Responsible Use

PyMap2 is intended for use on networks you own or have explicit written permission to scan. Unauthorised port scanning may be illegal in your jurisdiction. Always obtain proper authorisation before scanning any network.

---

## Author

**James Ball** — [jamescharlesball@gmail.com](mailto:jamescharlesball@gmail.com)
