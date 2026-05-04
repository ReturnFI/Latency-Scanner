import ssl
import socket
import time
import ipaddress
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


@dataclass
class HostResult:
    ip: str
    tcp_ms: Optional[float]
    open_port: Optional[int]

    @property
    def best_ms(self) -> float:
        return self.tcp_ms if self.tcp_ms is not None else float("inf")

    @property
    def reachable(self) -> bool:
        return self.tcp_ms is not None


def color_ms(ms: Optional[float]) -> str:
    if ms is None:
        return f"{DIM}{'—':>10}{RESET}"
    c = GREEN if ms <= 30 else (YELLOW if ms <= 100 else RED)
    return f"{c}{ms:>8.2f} ms{RESET}"


def latency_bar(ms: Optional[float], width: int = 20) -> str:
    if ms is None:
        return " " * width
    filled = min(int(ms / 5), width)
    empty  = width - filled
    c = GREEN if ms <= 30 else (YELLOW if ms <= 100 else RED)
    return f"{c}{'█' * filled}{DIM}{'░' * empty}{RESET}"


def tcp_probe_plain(ip: str, port: int, timeout: float, sni: Optional[str]) -> Optional[float]:
    """HTTP HEAD with Host header for port 80 / plain TCP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        err = s.connect_ex((ip, port))
        elapsed = (time.perf_counter() - t0) * 1000
        if err != 0:
            s.close()
            return None
        if sni:
            host = sni
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(request.encode())
            resp = s.recv(64)
            s.close()
            if resp:
                return round(elapsed, 3)
            return None
        s.close()
        return round(elapsed, 3)
    except OSError:
        return None


def tcp_probe_tls(ip: str, port: int, timeout: float, sni: str) -> Optional[float]:
    """TLS handshake with SNI for port 443."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        t0  = time.perf_counter()
        err = raw.connect_ex((ip, port))
        if err != 0:
            raw.close()
            return None
        conn = ctx.wrap_socket(raw, server_hostname=sni)
        conn.do_handshake()
        elapsed = (time.perf_counter() - t0) * 1000
        conn.close()
        return round(elapsed, 3)
    except (ssl.SSLError, OSError):
        return None


def probe_port(ip: str, port: int, timeout: float, retries: int, sni: Optional[str]) -> Optional[float]:
    samples = []
    for _ in range(retries):
        if sni and port == 443:
            result = tcp_probe_tls(ip, port, timeout, sni)
        else:
            result = tcp_probe_plain(ip, port, timeout, sni)
        if result is not None:
            samples.append(result)
    return round(sum(samples) / len(samples), 3) if samples else None


def scan_host(ip: str, ports: list[int], timeout: float, retries: int, sni: Optional[str]) -> HostResult:
    tcp_ms: Optional[float]  = None
    open_port: Optional[int] = None
    for port in ports:
        result = probe_port(ip, port, timeout, retries, sni)
        if result is not None and (tcp_ms is None or result < tcp_ms):
            tcp_ms    = result
            open_port = port
    return HostResult(ip=ip, tcp_ms=tcp_ms, open_port=open_port)


def parse_target(target: str) -> list[str]:
    target = target.strip()
    if not target or target.startswith("#"):
        return []
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        pass
    try:
        socket.inet_aton(target)
        return [target]
    except socket.error:
        pass
    return []


def load_targets(file_path: str) -> list[str]:
    ips = []
    try:
        with open(file_path) as f:
            for line in f:
                ips.extend(parse_target(line))
    except FileNotFoundError:
        print(f"\n  {RED}[error]{RESET} File not found: {file_path}\n")
        sys.exit(1)
    return ips


def write_file_header(f, args, total: int, timestamp: str):
    f.write("=" * 60 + "\n")
    f.write("  TCP Latency Scanner\n")
    f.write("=" * 60 + "\n")
    f.write(f"  Started : {timestamp}\n")
    f.write(f"  Targets : {total}\n")
    f.write(f"  Ports   : {', '.join(map(str, args.ports))}\n")
    f.write(f"  SNI     : {args.sni or '—'}\n")
    f.write(f"  Timeout : {args.timeout}s\n")
    f.write(f"  Retries : {args.retries}\n")
    f.write("=" * 60 + "\n\n")
    f.write("  Live results (discovery order):\n\n")
    f.write(f"  {'#':<5}  {'IP Address':<18}  {'TCP Avg':>10}  {'Port':>6}\n")
    f.write(f"  {'-'*5}  {'-'*18}  {'-'*10}  {'-'*6}\n")
    f.flush()


def append_result(f, rank: int, r: HostResult):
    tcp_str  = f"{r.tcp_ms:.2f} ms" if r.tcp_ms is not None else "—"
    port_str = str(r.open_port) if r.open_port else "—"
    f.write(f"  {rank:<5}  {r.ip:<18}  {tcp_str:>10}  {port_str:>6}\n")
    f.flush()


def write_file_summary(f, ranked: list, top: int):
    top_results = ranked[:top]
    f.write(f"\n\n{'=' * 60}\n")
    f.write(f"  Top {top} by latency\n")
    f.write(f"{'=' * 60}\n\n")
    f.write(f"  {'#':<5}  {'IP Address':<18}  {'TCP Avg':>10}  {'Port':>6}\n")
    f.write(f"  {'-'*5}  {'-'*18}  {'-'*10}  {'-'*6}\n")
    for i, r in enumerate(top_results, 1):
        append_result(f, i, r)
    best = top_results[0]
    f.write(f"\n  Best host : {best.ip}\n")
    f.write(f"  TCP avg   : {best.tcp_ms} ms  (port {best.open_port})\n")
    f.write(f"\n  Finished  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def run_scan(targets: list[str], args):
    total = len(targets)
    if total == 0:
        print(f"\n  {RED}[error]{RESET} No valid targets provided.\n")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print()
    print(f"  {BOLD}Latency Scanner{RESET}  {DIM}{timestamp}{RESET}")
    print(f"  {DIM}{'─' * 44}{RESET}")
    print(f"  {DIM}Targets {RESET}  {WHITE}{total}{RESET}")
    print(f"  {DIM}Ports   {RESET}  {WHITE}{', '.join(map(str, args.ports))}{RESET}")
    print(f"  {DIM}SNI     {RESET}  {WHITE}{args.sni or '—'}{RESET}")
    print(f"  {DIM}Timeout {RESET}  {args.timeout}s   {DIM}Retries{RESET}  {args.retries}   {DIM}Workers{RESET}  {args.workers}")
    print(f"  {DIM}Output  {RESET}  {args.output}")
    print(f"  {DIM}{'─' * 44}{RESET}")
    print()

    results: list[HostResult] = []
    done  = 0
    rank  = 0

    out = open(args.output, "w", encoding="utf-8")
    write_file_header(out, args, total, timestamp)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_host, ip, args.ports, args.timeout, args.retries, args.sni): ip
            for ip in targets
        }
        for future in as_completed(futures):
            r = future.result()
            done += 1
            if r.reachable:
                results.append(r)
                rank += 1
                append_result(out, rank, r)

            pct    = done / total * 100
            filled = int(pct / 5)
            bar    = f"{GREEN}{'█' * filled}{DIM}{'░' * (20 - filled)}{RESET}"
            sys.stdout.write(
                f"\r  {bar}  {WHITE}{pct:>5.1f}%{RESET}  "
                f"{DIM}scanned{RESET} {done}/{total}  "
                f"{GREEN}↑ {len(results)} reachable{RESET}   "
            )
            sys.stdout.flush()

    print("\n")

    if not results:
        out.write("\n  No reachable hosts found.\n")
        out.close()
        print(f"  {RED}No reachable hosts found.{RESET}")
        print()
        print(f"  {DIM}Suggestions:{RESET}")
        print(f"  {DIM}  • Provide SNI/Host     --sni cdn.example.com{RESET}")
        print(f"  {DIM}  • Try port 443         --ports 443{RESET}")
        print(f"  {DIM}  • Raise timeout        --timeout 3.0{RESET}")
        print()
        return

    ranked      = sorted(results, key=lambda r: r.best_ms)
    top_results = ranked[: args.top]

    write_file_summary(out, ranked, args.top)
    out.close()

    W_IP   = 18
    W_TCP  = 12
    W_PORT =  6
    W_BAR  = 22
    W_TOT  = 5 + W_IP + W_TCP + W_PORT + W_BAR + 8

    print(f"  {BOLD}Top {len(top_results)}{RESET}  {DIM}{len(ranked)} reachable  ·  {total} scanned{RESET}")
    print()
    print(f"  {DIM}{'#':<5}  {'IP Address':<{W_IP}}  {'TCP Avg':>{W_TCP}}  {'Port':>{W_PORT}}  {'Latency':<{W_BAR}}{RESET}")
    print(f"  {DIM}{'─' * W_TOT}{RESET}")

    for i, r in enumerate(top_results, 1):
        port_str  = str(r.open_port) if r.open_port else "—"
        rank_fmt  = f"{BOLD}{WHITE}{i}{RESET}" if i == 1 else f"{DIM}{i}{RESET}"
        print(
            f"  {rank_fmt:<14}  "
            f"{CYAN}{r.ip:<{W_IP}}{RESET}  "
            f"{color_ms(r.tcp_ms):>{W_TCP + 10}}  "
            f"{DIM}{port_str:>{W_PORT}}{RESET}  "
            f"{latency_bar(r.tcp_ms, W_BAR)}"
        )

    print(f"  {DIM}{'─' * W_TOT}{RESET}")
    print()

    best = top_results[0]
    print(f"  {BOLD}Best{RESET}  {CYAN}{best.ip}{RESET}   {DIM}tcp{RESET} {color_ms(best.tcp_ms)}  {DIM}port {best.open_port}{RESET}")
    print()
    print(f"  {DIM}Saved → {args.output}{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="TCP latency scanner with SNI/Host support",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    src = parser.add_argument_group("targets")
    src.add_argument("--ip",   nargs="+", metavar="IP/CIDR", help="One or more IPs or CIDR ranges")
    src.add_argument("--file", metavar="PATH",               help="File with one IP or CIDR per line")

    opt = parser.add_argument_group("options")
    opt.add_argument("--ports",   nargs="+", type=int, required=True, metavar="PORT",
                     help="TCP ports to probe  e.g. --ports 80 443")
    opt.add_argument("--sni",     default=None, metavar="HOST",
                     help="SNI hostname for TLS (443) and HTTP Host header (80)\n"
                          "e.g. --sni cdn.example.com")
    opt.add_argument("--timeout", type=float, default=2.0,  metavar="SEC")
    opt.add_argument("--retries", type=int,   default=3,    metavar="N")
    opt.add_argument("--workers", type=int,   default=200,  metavar="N")
    opt.add_argument("--top",     type=int,   default=10,   metavar="N")
    opt.add_argument("--output",  default="results.txt",    metavar="FILE")

    args = parser.parse_args()

    if not args.ip and not args.file:
        parser.error("provide at least one of --ip or --file")

    targets: list[str] = []
    if args.file:
        targets.extend(load_targets(args.file))
    if args.ip:
        for entry in args.ip:
            parsed = parse_target(entry)
            if not parsed:
                print(f"  {YELLOW}[warn]{RESET} Cannot parse target: {entry}")
            targets.extend(parsed)

    targets = list(dict.fromkeys(targets))
    run_scan(targets, args)


if __name__ == "__main__":
    main()
