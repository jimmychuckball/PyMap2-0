#!/usr/bin/env python3
"""
Async Network Port Scanner v2.0.0
Made by James Ball
"""

import asyncio
import csv
import ipaddress
import socket
import time
import signal
import random
import argparse
import logging
import os
import sys
import threading
from datetime import datetime


# =====================================================================
# CONSTANTS
# =====================================================================

VERSION = "2.0.0"
AUTHOR  = "James Ball"

DEFAULT_NETWORK        = "10.0.0.0/8"
DEFAULT_PORTS          = "22,80,443,9100"
DEFAULT_TIMEOUT        = 1.0
DEFAULT_CONCURRENCY    = 5000
DEFAULT_OUTPUT         = "scan_results.csv"
DEFAULT_LOG            = "scan.log"
DEFAULT_FLUSH_INTERVAL = 30
MAX_HOSTS              = 100_000_000

TOP_20_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
    "1723,3306,3389,5900,8080"
)
TOP_100_PORTS = (
    "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,"
    "139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,"
    "548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,"
    "1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,"
    "3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,"
    "5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,"
    "9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
)

CSV_FIELDS = ["ip", "port", "status", "hostname", "banner", "timestamp"]


# =====================================================================
# STARTUP BANNER
# =====================================================================

def print_banner():
    print("=" * 70)
    print(f"  Async Network Port Scanner  v{VERSION}  |  Made by {AUTHOR}")
    print("=" * 70)
    print(f"""
  USAGE
    python this-works.py [OPTIONS]
    Run with no arguments for interactive mode.

  TARGET  (pick one)
    -n, --network CIDR     IPv4 or IPv6 CIDR range to scan
                           e.g.  192.168.1.0/24   fd00::/120
    -f, --file PATH        Text file with one IP per line.
                           Blank lines and lines starting with # are skipped.

  PORTS
    -p, --ports PORTS      Comma-separated ports or ranges, e.g. 22,80,443-445
                           Presets:  top20  |  top100
                           Default:  {DEFAULT_PORTS}

  TUNING
    -t, --timeout SECS     TCP connect timeout in seconds  (default: {DEFAULT_TIMEOUT})
    -c, --concurrency N    Max simultaneous connections    (default: {DEFAULT_CONCURRENCY})
                           CAVEAT: values above ~10 000 may exhaust OS file
                           descriptors. Lower if you see "Too many open files".
    --flush-interval SECS  Write CSV every N seconds  (default: {DEFAULT_FLUSH_INTERVAL})

  OUTPUT
    -o, --output FILE      CSV results file  (default: {DEFAULT_OUTPUT})
    -l, --log FILE         Audit log file    (default: {DEFAULT_LOG})

  OPTIONAL FEATURES
    --banner               Grab service banners from open ports.
                           CAVEAT: adds latency per open port. Lower --concurrency
                           and raise --timeout when combining with this flag.
    --resolve              Reverse-DNS each open IP for a hostname.
                           CAVEAT: slow on large ranges — DNS queries are serial
                           per host and will significantly increase scan time.
    --shuffle              Randomise scan order to avoid sequential sweeps.
                           CAVEAT: loads all targets into memory before starting.
    --log-closed           Record closed/filtered ports in the CSV as well.
                           CAVEAT: massively increases file size on large ranges.
                           A full /8 scan at 4 ports = ~67 M rows.
    --resume               Skip IP:port pairs already present in the output CSV.
                           CAVEAT: the original output file must be intact and
                           use the same filename. Partially corrupt files may
                           cause incorrect skips.

  CONTROLS DURING SCAN
    p + Enter              Pause scanning
    r + Enter              Resume scanning
    q + Enter              Save buffered results and quit
    Ctrl+C                 Graceful exit — saves buffered results first.
                           Press twice to force-quit immediately.

  EXAMPLES
    python this-works.py -n 192.168.0.0/16 -p top20 --banner --resolve
    python this-works.py -f targets.txt -p 22,80,443 --shuffle --resume
    python this-works.py -n 10.0.0.0/8 -p 80,443 -c 2000 -o web.csv
    python this-works.py --help
""")
    print("=" * 70)
    print()


# =====================================================================
# ARGUMENT PARSER
# =====================================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="this-works.py",
        description=f"Async Network Port Scanner v{VERSION} by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "-n", "--network", metavar="CIDR",
        help="IPv4 or IPv6 CIDR range to scan (e.g. 192.168.1.0/24 or fd00::/120)",
    )
    target.add_argument(
        "-f", "--file", metavar="PATH",
        help="Text file of IP addresses, one per line (# comments and blanks skipped)",
    )

    parser.add_argument(
        "-p", "--ports", default=None, metavar="PORTS",
        help=f"Ports: comma-separated, ranges, or top20/top100 (default: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECS",
        help=f"TCP connect timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, metavar="N",
        help=f"Max simultaneous connections (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "-o", "--output", default=DEFAULT_OUTPUT, metavar="FILE",
        help=f"CSV output file (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "-l", "--log", default=DEFAULT_LOG, metavar="FILE",
        help=f"Audit log file (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--flush-interval", type=int, default=DEFAULT_FLUSH_INTERVAL, metavar="SECS",
        help=f"Flush results to CSV every N seconds (default: {DEFAULT_FLUSH_INTERVAL})",
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Grab service banners from open ports (slower — lower -c when using)",
    )
    parser.add_argument(
        "--resolve", action="store_true",
        help="Reverse-DNS lookup for each open IP (slow on large ranges)",
    )
    parser.add_argument(
        "--shuffle", action="store_true",
        help="Randomise scan order (loads all targets into memory first)",
    )
    parser.add_argument(
        "--log-closed", action="store_true", dest="log_closed",
        help="Record closed/filtered ports in the CSV (greatly increases file size)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip IP:port pairs already recorded in the output CSV",
    )

    return parser


# =====================================================================
# VALIDATION & PARSING
# =====================================================================

def validate_cidr(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        print(f"[!] Invalid CIDR '{cidr}': {exc}")
        sys.exit(1)


def parse_ports(port_string):
    preset = port_string.strip().lower()

    if preset == "top20":
        port_string = TOP_20_PORTS
    elif preset == "top100":
        port_string = TOP_100_PORTS

    ports = []

    for part in port_string.split(","):
        part = part.strip()

        if not part:
            continue

        try:
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)

                if not (0 < start <= 65535 and 0 < end <= 65535 and start <= end):
                    print(f"[!] Port range out of bounds: {part}")
                    sys.exit(1)

                ports.extend(range(start, end + 1))
            else:
                port = int(part)

                if not (0 < port <= 65535):
                    print(f"[!] Port out of bounds: {port}")
                    sys.exit(1)

                ports.append(port)

        except ValueError:
            print(f"[!] Invalid port entry: '{part}'")
            sys.exit(1)

    if not ports:
        print("[!] No valid ports specified.")
        sys.exit(1)

    return sorted(set(ports))


# =====================================================================
# IP FILE LOADER
# =====================================================================

def load_ip_file(filename):
    hosts = []

    try:
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                try:
                    hosts.append(ipaddress.ip_address(line))
                except ValueError:
                    print(f"[WARN] Line {lineno}: skipping invalid entry '{line}'")

    except FileNotFoundError:
        print(f"[!] File not found: {filename}")
        sys.exit(1)

    return hosts


# =====================================================================
# RESUME — load already-scanned pairs
# =====================================================================

def load_skip_set(filename):
    skip = set()

    if not os.path.exists(filename):
        return skip

    try:
        with open(filename, "r", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    skip.add((row["ip"], int(row["port"])))
                except (KeyError, ValueError):
                    pass

        print(f"[+] Resume: {len(skip):,} already-scanned pairs loaded from {filename}")

    except Exception as exc:
        print(f"[WARN] Could not read resume file: {exc}")

    return skip


# =====================================================================
# CSV WRITER
# =====================================================================

def write_csv(filename, rows):
    file_exists = os.path.exists(filename)

    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")

        if not file_exists:
            writer.writeheader()

        writer.writerows(rows)


# =====================================================================
# LOGGING
# =====================================================================

def setup_logging(log_file):
    logger = logging.getLogger("scanner")
    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)

    return logger


# =====================================================================
# KEYBOARD LISTENER  (pause / resume / quit)
# =====================================================================

def keyboard_listener(loop, pause_event, stop_flag):
    while not stop_flag[0]:
        try:
            line = sys.stdin.readline()

            if not line:
                break

            cmd = line.strip().lower()

            if cmd == "p":
                loop.call_soon_threadsafe(pause_event.clear)
                print("\n[~] Scan PAUSED. Type 'r' + Enter to resume, 'q' + Enter to quit.")

            elif cmd == "r":
                loop.call_soon_threadsafe(pause_event.set)
                print("\n[~] Scan RESUMED.")

            elif cmd == "q":
                stop_flag[0] = True
                loop.call_soon_threadsafe(pause_event.set)
                print("\n[!] Quit requested. Saving results...")
                break

        except Exception:
            break


# =====================================================================
# SCAN COROUTINE
# =====================================================================

async def scan_port(ip, port, timeout, sem, results, stats, config, pause_event, stop_flag):

    if stop_flag[0]:
        return

    await pause_event.wait()

    if stop_flag[0]:
        return

    async with sem:

        stats["attempted"] += 1
        ip_str = str(ip)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_str, port),
                timeout=timeout,
            )

            banner = ""
            if config["banner"]:
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=2.0)
                    banner = data.decode("utf-8", errors="replace").strip()
                    banner = " ".join(banner.split())[:200]
                except Exception:
                    pass

            hostname = ""
            if config["resolve"]:
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyaddr, ip_str
                    )
                    hostname = result[0]
                except Exception:
                    pass

            stats["open"] += 1

            results.append({
                "ip":        ip_str,
                "port":      port,
                "status":    "open",
                "hostname":  hostname,
                "banner":    banner,
                "timestamp": datetime.utcnow().isoformat(),
            })

            extra = ""
            if hostname:
                extra += f" | {hostname}"
            if banner:
                extra += f" | {banner[:60]}"

            print(f"\n[OPEN] {ip_str}:{port}{extra}")

            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

        except Exception:
            if config["log_closed"]:
                results.append({
                    "ip":        ip_str,
                    "port":      port,
                    "status":    "closed",
                    "hostname":  "",
                    "banner":    "",
                    "timestamp": datetime.utcnow().isoformat(),
                })


# =====================================================================
# STATUS DISPLAY
# =====================================================================

async def status_display(stats, total_targets, start_time, pause_event, stop_flag):

    while not stats["finished"] and not stop_flag[0]:

        elapsed = time.time() - start_time
        rate    = int(stats["attempted"] / elapsed) if elapsed > 0 else 0
        percent = (stats["attempted"] / total_targets * 100) if total_targets > 0 else 0
        state   = "PAUSED " if not pause_event.is_set() else "RUNNING"

        print(
            f"\r[{state}] "
            f"{stats['attempted']:,}/{total_targets:,} "
            f"({percent:.1f}%) | "
            f"Open: {stats['open']:,} | "
            f"Rate: {rate:,}/s | "
            f"Elapsed: {int(elapsed)}s   ",
            end="",
            flush=True,
        )

        await asyncio.sleep(2)

    print()


# =====================================================================
# MAIN SCANNER COROUTINE
# =====================================================================

async def scanner(hosts, source_label, ports, config, pause_event, stop_flag, logger):

    sem      = asyncio.Semaphore(config["concurrency"])
    results  = []
    skip_set = load_skip_set(config["output"]) if config["resume"] else set()
    stats    = {"attempted": 0, "open": 0, "finished": False}
    skipped  = 0

    if config["shuffle"]:
        random.shuffle(hosts)

    total_targets = len(hosts) * len(ports)

    logger.info(
        f"Scan started | target={source_label} | hosts={len(hosts)} | "
        f"ports={ports} | concurrency={config['concurrency']} | "
        f"timeout={config['timeout']} | output={config['output']}"
    )

    print("\n[+] Scan Configuration")
    print(f"    Target         : {source_label}")
    print(f"    Hosts          : {len(hosts):,}")
    print(f"    Ports          : {ports}")
    print(f"    Timeout        : {config['timeout']}s")
    print(f"    Concurrency    : {config['concurrency']}")
    print(f"    Output         : {config['output']}")
    print(f"    Log            : {config['log']}")
    print(f"    Banner grab    : {config['banner']}")
    print(f"    Reverse DNS    : {config['resolve']}")
    print(f"    Shuffle order  : {config['shuffle']}")
    print(f"    Log closed     : {config['log_closed']}")
    print(f"    Resume         : {config['resume']} ({len(skip_set):,} pairs skipped)")
    print(f"    Flush interval : {config['flush_interval']}s")
    print(f"    Total checks   : {total_targets:,}")
    print()
    print("  Controls: p=pause  r=resume  q=quit  Ctrl+C=graceful exit")
    print()

    start_time      = time.time()
    last_flush_time = start_time
    batch_limit     = config["concurrency"] * 10

    status_task = asyncio.create_task(
        status_display(stats, total_targets, start_time, pause_event, stop_flag)
    )

    tasks = []

    for ip in hosts:

        if stop_flag[0]:
            break

        for port in ports:

            if stop_flag[0]:
                break

            ip_str = str(ip)

            if (ip_str, port) in skip_set:
                skipped += 1
                stats["attempted"] += 1
                continue

            tasks.append(
                scan_port(
                    ip, port, config["timeout"], sem,
                    results, stats, config, pause_event, stop_flag,
                )
            )

        if len(tasks) >= batch_limit or stop_flag[0]:

            await asyncio.gather(*tasks)
            tasks.clear()

            now = time.time()

            if results and (now - last_flush_time >= config["flush_interval"] or stop_flag[0]):
                write_csv(config["output"], results)
                logger.info(f"Flushed {len(results):,} results to {config['output']}")
                results.clear()
                last_flush_time = now

    if tasks:
        await asyncio.gather(*tasks)

    if results:
        write_csv(config["output"], results)
        logger.info(f"Flushed final {len(results):,} results to {config['output']}")

    stats["finished"] = True
    await status_task

    elapsed = int(time.time() - start_time)

    logger.info(
        f"Scan complete | open={stats['open']} | "
        f"attempted={stats['attempted']} | elapsed={elapsed}s"
    )

    print("\n[+] Scan Complete")

    if skipped:
        print(f"[+] Skipped (resume)  : {skipped:,}")

    print(f"[+] Open Ports Found  : {stats['open']:,}")
    print(f"[+] Total Attempts    : {stats['attempted']:,}")
    print(f"[+] Total Time        : {elapsed}s")
    print(f"[+] Results Saved To  : {config['output']}")
    print(f"[+] Log Saved To      : {config['log']}")


# =====================================================================
# INTERACTIVE HELPERS
# =====================================================================

def ask(prompt, default):
    value = input(f"  {prompt} [{default}]: ").strip()
    return value if value else str(default)


def ask_bool(prompt, default=False):
    hint  = "Y/n" if default else "y/N"
    value = input(f"  {prompt} [{hint}]: ").strip().lower()

    if not value:
        return default

    return value in ("y", "yes")


# =====================================================================
# ENTRY POINT
# =====================================================================

def main():
    print_banner()

    parser = build_parser()
    args   = parser.parse_args()

    cli_mode = bool(args.network or args.file)

    # ------------------------------------------------------------------
    # Resolve hosts
    # ------------------------------------------------------------------

    if args.network:
        net   = validate_cidr(args.network)
        hosts = list(net.hosts())

        if not hosts:
            print("[!] Network has no usable host addresses.")
            sys.exit(1)

        if net.num_addresses > MAX_HOSTS:
            print(f"[!] Range contains {net.num_addresses:,} addresses (max {MAX_HOSTS:,}).")
            print("    For IPv6 use a smaller prefix, e.g. /112 or /120.")
            sys.exit(1)

        if net.num_addresses > 1_000_000:
            print(f"[WARN] Large range: {net.num_addresses:,} addresses. This may take a long time.")

        source_label = args.network

    elif args.file:
        hosts        = load_ip_file(args.file)
        source_label = args.file

        if not hosts:
            print("[!] No valid IPs loaded from file.")
            sys.exit(1)

    else:
        # Interactive target selection
        print("  Input mode:")
        print("    1 = CIDR range (IPv4 or IPv6)")
        print("    2 = Text file of IP addresses")
        mode = input("  Select [1]: ").strip() or "1"
        print()

        if mode == "2":
            filename     = input("  IP file path: ").strip()
            hosts        = load_ip_file(filename)
            source_label = filename

            if not hosts:
                print("[!] No valid IPs found in file.")
                sys.exit(1)

            print(f"  [+] Loaded {len(hosts):,} IPs\n")

        else:
            cidr  = ask("Target CIDR", DEFAULT_NETWORK)
            net   = validate_cidr(cidr)
            hosts = list(net.hosts())
            source_label = cidr

            if not hosts:
                print("[!] Network has no usable host addresses.")
                sys.exit(1)

            if net.num_addresses > MAX_HOSTS:
                print(f"[!] Range too large ({net.num_addresses:,} addresses). Max {MAX_HOSTS:,}.")
                sys.exit(1)

            if net.num_addresses > 1_000_000:
                print(f"  [WARN] Large range: {net.num_addresses:,} addresses.")

        print()

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------

    if args.ports:
        ports_str = args.ports
    elif cli_mode:
        ports_str = DEFAULT_PORTS
    else:
        ports_str = ask("Ports (or top20/top100)", DEFAULT_PORTS)

    ports = parse_ports(ports_str)

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    if cli_mode:
        config = {
            "timeout":        args.timeout,
            "concurrency":    args.concurrency,
            "output":         args.output,
            "log":            args.log,
            "flush_interval": args.flush_interval,
            "banner":         args.banner,
            "resolve":        args.resolve,
            "shuffle":        args.shuffle,
            "log_closed":     args.log_closed,
            "resume":         args.resume,
        }
    else:
        print("\n  Tuning (press Enter to accept defaults):\n")
        timeout     = float(ask("Timeout (secs)", DEFAULT_TIMEOUT))
        concurrency = int(ask("Concurrency", DEFAULT_CONCURRENCY))
        output      = ask("Output CSV", DEFAULT_OUTPUT)
        log_file    = ask("Log file", DEFAULT_LOG)
        print()
        print("  Optional features (adds capability but may slow the scan):\n")
        banner     = ask_bool("Grab service banners?", False)
        resolve    = ask_bool("Reverse-DNS open IPs?", False)
        shuffle    = ask_bool("Shuffle scan order?", False)
        log_closed = ask_bool("Log closed ports too?", False)
        resume     = ask_bool("Resume from existing CSV?", False)

        config = {
            "timeout":        timeout,
            "concurrency":    concurrency,
            "output":         output,
            "log":            log_file,
            "flush_interval": DEFAULT_FLUSH_INTERVAL,
            "banner":         banner,
            "resolve":        resolve,
            "shuffle":        shuffle,
            "log_closed":     log_closed,
            "resume":         resume,
        }

    logger = setup_logging(config["log"])

    # ------------------------------------------------------------------
    # Async setup
    # ------------------------------------------------------------------

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    pause_event = asyncio.Event()
    pause_event.set()

    stop_flag = [False]

    original_sigint = signal.getsignal(signal.SIGINT)

    def handle_sigint(sig, frame):
        if stop_flag[0]:
            print("\n[!] Force quitting.")
            os._exit(1)

        stop_flag[0] = True
        loop.call_soon_threadsafe(pause_event.set)
        print("\n[!] Ctrl+C caught — finishing current batch and saving results...")
        print("    Press Ctrl+C again to force quit immediately.")

    signal.signal(signal.SIGINT, handle_sigint)

    kb_thread = threading.Thread(
        target=keyboard_listener,
        args=(loop, pause_event, stop_flag),
        daemon=True,
    )
    kb_thread.start()

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    try:
        loop.run_until_complete(
            scanner(hosts, source_label, ports, config, pause_event, stop_flag, logger)
        )
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        stop_flag[0] = True
        loop.close()


if __name__ == "__main__":
    main()
