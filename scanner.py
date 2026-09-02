import asyncio
import re
import socket
import ipaddress
import concurrent.futures
import threading
import time
from datetime import datetime
from dataclasses import dataclass


class ScanError(Exception):
    pass


@dataclass
class ScanResult:
    command: str
    output: str


def validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ScanError("Цель не может быть пустой.")
    if "/" in target:
        raise ScanError("Сканирование подсетей недоступно. Введите одиночный IP или домен.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ScanError(f"Некорректный IP: {target}")
        return target
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", target):
        return target
    raise ScanError(f"Некорректная цель: {target}")


def validate_port(port_str: str) -> int:
    port_str = port_str.strip()
    if not port_str.isdigit():
        raise ScanError(f"Порт должен быть числом, получено: {port_str}")
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ScanError(f"Порт должен быть от 1 до 65535, получено: {port}")
    return port


# Цвета для красивого вывода в консоль (опционально)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

class NetworkScanner:
    def __init__(self, timeout=1.0, max_threads=100):
        """
        timeout: таймаут на подключение (сек)
        max_threads: кол-во потоков для параллельного сканирования
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = {}
        self.alive_hosts = []
        
    def ping_host(self, ip):
        """Проверяет, отвечает ли хост на ICMP (через сырой сокет)"""
        try:
            # Для ICMP нужно создавать сырой сокет (требует прав администратора)
            # Используем упрощённый метод - попытка TCP подключения на порт 80
            # Это работает без прав и почти так же надёжно
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), 80))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        """Сканирует один порт на указанном IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), port))
            
            if result == 0:
                # Порт открыт
                service = self.get_service_name(port)
                banner = self.get_banner(sock, port)
                return (port, service, banner)
            sock.close()
        except Exception as e:
            pass
        return None
    
    PORT_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SMTP/Submission", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana",
        1883: "MQTT", 5672: "RabbitMQ", 6443: "Kubernetes",
        10250: "Kubelet", 2379: "etcd",
    }

    def get_service_name(self, port):
        if port in self.PORT_SERVICES:
            return self.PORT_SERVICES[port]
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def get_banner(self, sock, port):
        banner = ""
        try:
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
                data = sock.recv(1024)
                raw = data.decode("utf-8", errors="ignore")
                lines = raw.split("\r\n")
                server = ""
                title = ""
                for line in lines:
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                    if line.lower().startswith("x-powered-by:"):
                        server = line.split(":", 1)[1].strip()
                    if line.lower().startswith("<title>"):
                        title = line.split("<title>", 1)[-1].split("</title>")[0][:60]
                parts = []
                if server:
                    parts.append(server)
                if title:
                    parts.append(f'"{title}"')
                banner = " | ".join(parts) if parts else raw.split("\r\n")[0]
            elif port == 21:
                sock.settimeout(2)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="ignore").strip().split("\n")[0]
            elif port == 22:
                sock.settimeout(2)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="ignore").strip()
            elif port == 25:
                sock.settimeout(2)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="ignore").strip().split("\n")[0]
            elif port == 3306:
                sock.settimeout(2)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="ignore").split("\x00")[0].strip()
            elif port == 5432:
                pass  # PostgreSQL не отдаёт баннер без авторизации
            elif port == 6379:
                sock.send(b"INFO\r\n")
                sock.settimeout(1)
                data = sock.recv(512)
                raw = data.decode("utf-8", errors="ignore")
                ver_match = raw.split("redis_version:")[-1].split("\r\n")[0] if "redis_version" in raw else ""
                banner = f"Redis {ver_match}" if ver_match else "Redis"
            elif port == 27017:
                sock.send(b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                sock.settimeout(1)
                data = sock.recv(256)
                banner = "MongoDB" if data else "MongoDB (no auth info)"
            else:
                sock.settimeout(0.5)
                data = sock.recv(256)
                banner = data.decode("utf-8", errors="ignore").strip()[:80]
        except:
            banner = ""
        return banner

    def scan_host(self, ip, ports):
        """Сканирует все порты для одного хоста"""
        self.open_ports[str(ip)] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Создаём задачи для всех портов
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    port, service, banner = result
                    self.open_ports[str(ip)].append({
                        'port': port,
                        'service': service,
                        'banner': banner
                    })
    
    def scan_network(self, network_cidr, ports):
        """
        Сканирует всю сеть
        network_cidr: например "192.168.1.0/24"
        ports: список портов для сканирования
        """
        print(f"{YELLOW}[*] Scanning network: {network_cidr}{RESET}")
        print(f"{YELLOW}[*] Ports: {ports}{RESET}")
        print(f"{YELLOW}[*] Started at: {datetime.now()}{RESET}\n")
        
        # Генерируем все IP в подсети
        network = ipaddress.ip_network(network_cidr, strict=False)
        hosts = list(network.hosts())
        
        # Сначала находим живые хосты (быстрое сканирование)
        print(f"{YELLOW}[*] Discovering alive hosts...{RESET}")
        alive = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {
                executor.submit(self.ping_host, ip): ip 
                for ip in hosts
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                if future.result():
                    alive.append(ip)
                    print(f"{GREEN}[+] Host {ip} is alive{RESET}")
        
        self.alive_hosts = alive
        
        if not alive:
            print(f"{RED}[-] No alive hosts found{RESET}")
            return
        
        # Теперь сканируем порты на живых хостах
        print(f"\n{YELLOW}[*] Scanning ports on {len(alive)} alive hosts...{RESET}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(lambda ip: self.scan_host(ip, ports), alive)
        
        # Выводим итоговый отчёт
        self.print_summary()
    
    def print_summary(self):
        """Выводит итоговый отчёт"""
        print("\n" + "="*60)
        print(f"{YELLOW}SCAN SUMMARY{RESET}")
        print("="*60)
        
        total_open = 0
        for ip, ports in self.open_ports.items():
            if ports:
                print(f"\n{GREEN}{ip}{RESET} ({len(ports)} open ports):")
                for p in ports:
                    print(f"  {p['port']}/{p['service']} - {p['banner'][:50]}")
                total_open += len(ports)
        
        print(f"\n{YELLOW}[*] Total hosts alive: {len(self.alive_hosts)}{RESET}")
        print(f"{YELLOW}[*] Total open ports: {total_open}{RESET}")
        print(f"{YELLOW}[*] Completed at: {datetime.now()}{RESET}")


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]


def _scan_sync(target: str, scan_type: str, port: int | None) -> ScanResult:
    # Одиночный хост: не сканируем сети, чтобы не нагружать сервер.
    if "/" in target:
        raise ScanError("Сканирование подсетей недоступно.")
    try:
        host = ipaddress.ip_address(target)
    except ValueError:
        host = target  # домен

    # Ограничения по нагрузке на сервер
    scanner = NetworkScanner(timeout=1.0, max_threads=50)

    if scan_type == "fast":
        ports_to_scan = [80, 443]
        cmd_desc = f"fast scan {target}"
    elif scan_type == "full":
        ports_to_scan = list(range(1, 1001))
        cmd_desc = f"full scan {target} (1-1000)"
    elif scan_type == "only_ports":
        ports_to_scan = DEFAULT_PORTS
        cmd_desc = f"port scan {target}"
    elif scan_type == "info":
        ports_to_scan = DEFAULT_PORTS
        cmd_desc = f"service info {target}"
    else:
        ports_to_scan = DEFAULT_PORTS
        cmd_desc = f"scan {target}"

    if port is not None:
        ports_to_scan = [port]
        cmd_desc = f"port {port} scan {target}"

    targets = [ipaddress.ip_address(target)] if isinstance(host, ipaddress.IPv4Address) else [target]

    SERVICE_ICONS = {
        "HTTP": "🌐", "HTTPS": "🔒", "SSH": "🔑", "FTP": "📁",
        "SMTP": "📧", "MySQL": "🐬", "PostgreSQL": "🐘", "Redis": "🔴",
        "RDP": "🖥️", "VNC": "📺", "SMB": "📂", "DNS": "🔍",
        "MongoDB": "🍃", "Elasticsearch": "🔎", "MQTT": "📡",
        "Telnet": "📡", "POP3": "📨", "IMAP": "📬", "NetBIOS": "📋",
        "Kubernetes": "☸️", "RabbitMQ": "🐇",
    }

    PORT_SERVICES_INFO = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        27017: "MongoDB", 9200: "Elasticsearch",
    }

    lines: list[str] = []
    lines.append("📡 TGMAP - Результаты сканирования")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"Цель: {target}")
    lines.append(f"Режим: {cmd_desc}")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━")

    for host in targets:
        host_str = str(host)
        scanner.open_ports[host_str] = []
        scanner.scan_host(host, ports_to_scan)

        open_list = scanner.open_ports.get(host_str, [])
        if not open_list:
            lines.append(f"\n{host_str}")
            lines.append("  ❌ Открытых портов не найдено")
        else:
            lines.append(f"\n{host_str} - {len(open_list)} открыто:")
            lines.append("")
            for p in sorted(open_list, key=lambda x: x["port"]):
                port_num = p["port"]
                svc = p["service"]
                icon = SERVICE_ICONS.get(svc, "▪️")
                info = PORT_SERVICES_INFO.get(port_num, "")
                label = info if info else svc
                banner = p.get("banner", "")
                lines.append(f"  {icon} {port_num}/tcp  {label}")
                if banner and banner != "No banner":
                    lines.append(f"     └ {banner[:100]}")

    total_open = sum(len(v) for v in scanner.open_ports.values())
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"✅ Готово: {len(targets)} хост(ов), {total_open} открытых портов")

    return ScanResult(command=cmd_desc, output="\n".join(lines))


async def run_nmap(target: str, scan_type: str = "fast", port: int | None = None) -> ScanResult:
    return await asyncio.to_thread(_scan_sync, target, scan_type, port)


# ============ ИСПОЛЬЗОВАНИЕ ============
if __name__ == "__main__":
    import sys

    t = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    result = asyncio.run(run_nmap(t, scan_type="fast"))
    print(result.output)