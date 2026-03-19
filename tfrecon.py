#!/usr/bin/env python3

import argparse
import socket
import sys
import ssl
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

BANNER = r"""
████████╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ██║   █████╗  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ██║   ██╔══╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
   ██║   ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

              TFRecon Framework
      Subdomain Enumeration + Port Scanner
"""

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 587,
    636, 873, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049,
    2082, 2083, 2222, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4000,
    4444, 5000, 5060, 5432, 5601, 5672, 5900, 5985, 5986, 6379, 6443,
    6667, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090,
    9200, 9300, 9418, 10000, 11211, 27017
]

SERVICE_MAP = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "smtp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8088: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def print_banner():
    print(BANNER)


def normalize_target(target: str) -> str:
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0]
    return target.split(":")[0]


def parse_ports(port_string: str):
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start = int(start)
            end = int(end)
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def save_results(output_file: str, lines):
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        print(f"\n[*] Results saved to {output_file}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")


# -------------------- SUBDOMAIN ENUMERATION --------------------

def get_crtsh_subdomains(domain: str):
    print(f"[*] Collecting subdomains from crt.sh for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        data = response.json()

        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.splitlines():
                sub = sub.strip().lower()
                if "*" in sub:
                    sub = sub.replace("*.", "")
                if sub.endswith(domain):
                    subdomains.add(sub)

    except Exception as e:
        print(f"[!] crt.sh request failed: {e}")

    return sorted(subdomains)


def resolve_host(host: str):
    try:
        ip = socket.gethostbyname(host)
        return host, ip
    except Exception:
        return host, None


def resolve_hosts(hosts, threads=30):
    print("[*] Resolving discovered hosts...\n")
    resolved = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_host, host): host for host in hosts}
        for future in as_completed(futures):
            host, ip = future.result()
            if ip:
                print(f"[+] {host:<40} -> {ip}")
                resolved.append((host, ip))
            else:
                print(f"[-] {host:<40} -> unresolved")

    return sorted(resolved, key=lambda x: x[0])


# -------------------- VERSION / BANNER DETECTION --------------------

def clean_text(text: str) -> str:
    text = text.replace("\r", " ").replace("\n", " ").strip()
    return re.sub(r"\s+", " ", text)


def recv_data(sock, size=512):
    try:
        data = sock.recv(size)
        return data.decode(errors="ignore")
    except Exception:
        return ""


def detect_http(host: str, port: int, timeout: float, use_ssl: bool = False):
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)

        sock = raw_sock
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: TFRecon\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        sock.sendall(request)
        data = recv_data(sock, 1024)
        sock.close()

        if not data:
            return None

        server = None
        for line in data.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break

        if server:
            return f"{'https' if use_ssl else 'http'} | {server}"

        first = clean_text(data[:100])
        return f"{'https' if use_ssl else 'http'} | {first}"
    except Exception:
        return None


def detect_ssh(sock):
    data = recv_data(sock, 200)
    if data:
        text = clean_text(data)
        if "SSH-" in text:
            return f"ssh | {text}"
    return "ssh"


def detect_ftp(sock):
    data = recv_data(sock, 300)
    if data:
        text = clean_text(data)
        return f"ftp | {text}"
    return "ftp"


def detect_smtp(sock, host):
    banner = recv_data(sock, 300)
    try:
        sock.sendall(f"EHLO {host}\r\n".encode())
        reply = recv_data(sock, 400)
        text = clean_text((banner + " " + reply).strip())
        if text:
            return f"smtp | {text[:120]}"
    except Exception:
        pass
    if banner:
        return f"smtp | {clean_text(banner)}"
    return "smtp"


def detect_pop3(sock):
    data = recv_data(sock, 300)
    if data:
        return f"pop3 | {clean_text(data)}"
    return "pop3"


def detect_imap(sock):
    banner = recv_data(sock, 300)
    try:
        sock.sendall(b"a001 CAPABILITY\r\n")
        reply = recv_data(sock, 400)
        text = clean_text((banner + " " + reply).strip())
        if text:
            return f"imap | {text[:120]}"
    except Exception:
        pass
    if banner:
        return f"imap | {clean_text(banner)}"
    return "imap"


def detect_mysql(sock):
    data = recv_data(sock, 300)
    if data:
        text = clean_text(data)
        return f"mysql | {text[:120]}"
    return "mysql"


def detect_generic(sock, port):
    data = recv_data(sock, 300)
    if data:
        return f"{SERVICE_MAP.get(port, 'unknown')} | {clean_text(data[:120])}"
    return SERVICE_MAP.get(port, "unknown")


def detect_service_version(host: str, port: int, timeout: float):
    service_name = SERVICE_MAP.get(port, "unknown")

    if port in [80, 8000, 8008, 8080, 8081, 8088, 8888]:
        result = detect_http(host, port, timeout, use_ssl=False)
        return result if result else service_name

    if port in [443, 8443, 5986]:
        result = detect_http(host, port, timeout, use_ssl=True)
        return result if result else service_name

    if port == 22:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return detect_ssh(sock)
        except Exception:
            return service_name

    if port == 21:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return detect_ftp(sock)
        except Exception:
            return service_name

    if port in [25, 465, 587]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return detect_smtp(sock, host)
        except Exception:
            return service_name

    if port in [110, 995]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return detect_pop3(sock)
        except Exception:
            return service_name

    if port in [143, 993]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return detect_imap(sock)
        except Exception:
            return service_name

    if port == 3306:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                return detect_mysql(sock)
        except Exception:
            return service_name

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if port == 3389:
                return "rdp"
            if port == 445:
                return "microsoft-ds"
            if port == 53:
                return "dns"

            return detect_generic(sock, port)
    except Exception:
        return service_name


# -------------------- PORT SCANNER --------------------

def scan_port(host: str, port: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            version = detect_service_version(host, port, timeout)
            return port, version
    except Exception:
        return None


def scan_target(host: str, ports, threads=100, timeout=1.0):
    print(f"[*] Scanning target: {host}")
    print(f"[*] Total ports queued: {len(ports)}\n")
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, version = result
                print(f"[+] Port {port:<5} open   Service: {version}")
                results.append((port, version))

    return sorted(results, key=lambda x: x[0])


# -------------------- MODES --------------------

def enum_mode(args):
    domain = normalize_target(args.domain)
    subs = get_crtsh_subdomains(domain)

    print(f"\n[*] Total subdomains discovered: {len(subs)}\n")
    output_lines = []

    if args.no_resolve:
        for sub in subs:
            print(f"[+] {sub}")
            output_lines.append(sub)
    else:
        resolved = resolve_hosts(subs, threads=args.threads)
        output_lines = [f"{host} -> {ip}" for host, ip in resolved]

    if args.output:
        save_results(args.output, output_lines)


def scan_mode(args):
    host = normalize_target(args.target)

    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top:
        ports = COMMON_PORTS
    else:
        ports = list(range(1, 1025))

    results = scan_target(
        host=host,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout
    )

    output_lines = [f"{host}:{port} -> {version}" for port, version in results]

    if args.output:
        save_results(args.output, output_lines)


def full_mode(args):
    domain = normalize_target(args.domain)
    subs = get_crtsh_subdomains(domain)

    print(f"\n[*] Total subdomains discovered: {len(subs)}\n")
    resolved = resolve_hosts(subs, threads=args.threads)

    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top:
        ports = COMMON_PORTS
    else:
        ports = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 139, 143, 445, 3306, 3389]

    output_lines = []

    for host, ip in resolved:
        print(f"\n{'=' * 70}")
        print(f"[*] Starting port scan for {host} ({ip})")
        print(f"{'=' * 70}\n")

        results = scan_target(
            host=host,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout
        )

        if not results:
            output_lines.append(f"{host} -> {ip} | No open ports found")
        else:
            for port, version in results:
                output_lines.append(f"{host} -> {ip} | Port {port} | {version}")

    if args.output:
        save_results(args.output, output_lines)


def build_parser():
    parser = argparse.ArgumentParser(
        description="TFRecon - Subdomain Enumeration and Port Scanner"
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    parser_enum = subparsers.add_parser("enum", help="Run subdomain enumeration")
    parser_enum.add_argument("-d", "--domain", required=True, help="Target domain")
    parser_enum.add_argument("-o", "--output", help="Output file")
    parser_enum.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution")
    parser_enum.add_argument("-t", "--threads", type=int, default=30, help="Thread count")
    parser_enum.set_defaults(func=enum_mode)

    parser_scan = subparsers.add_parser("scan", help="Run port scan against one target")
    parser_scan.add_argument("-T", "--target", required=True, help="Target host or IP")
    parser_scan.add_argument("-p", "--ports", help="Ports like 80,443,8000-8100")
    parser_scan.add_argument("--top", action="store_true", help="Scan common top ports")
    parser_scan.add_argument("-t", "--threads", type=int, default=100, help="Thread count")
    parser_scan.add_argument("--timeout", type=float, default=1.5, help="Socket timeout")
    parser_scan.add_argument("-o", "--output", help="Output file")
    parser_scan.set_defaults(func=scan_mode)

    parser_full = subparsers.add_parser("full", help="Enumerate subdomains then scan them")
    parser_full.add_argument("-d", "--domain", required=True, help="Target domain")
    parser_full.add_argument("-p", "--ports", help="Ports like 80,443,8000-8100")
    parser_full.add_argument("--top", action="store_true", help="Scan common top ports")
    parser_full.add_argument("-t", "--threads", type=int, default=60, help="Thread count")
    parser_full.add_argument("--timeout", type=float, default=1.5, help="Socket timeout")
    parser_full.add_argument("-o", "--output", help="Output file")
    parser_full.set_defaults(func=full_mode)

    return parser


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
