import socket
import ssl
from threading import Thread
import platform
from datetime import datetime
import uuid
import re
import zlib
import base64
import psutil
import cpuinfo
import time
import winreg

import siconfig


class SystemMonitor:
    @staticmethod
    def get_size(bytes_size, suffix="B"):
        factor = 1024
        for unit in ["", "K", "M", "G", "T", "P"]:
            if bytes_size < factor:
                return f"{bytes_size:.2f}{unit}{suffix}"
            bytes_size /= factor

    @staticmethod
    def get_dashboard_info():
        uname = platform.uname()
        svmem = psutil.virtual_memory()
        cpu_brand = cpuinfo.get_cpu_info().get('brand_raw', 'Unknown CPU')
        ip_addr = socket.gethostbyname(socket.gethostname())
        mac_addr = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

        lines = [
            "Dashboard Info",
            f"System: {uname.system} {uname.release} (Version: {uname.version})",
            f"Node Name: {uname.node}",
            f"Processor: {cpu_brand}",
            f"Total Memory: {SystemMonitor.get_size(svmem.total)}",
            f"IP Address: {ip_addr}",
            f"MAC Address: {mac_addr}",
            "-" * 40,
            f"Current CPU Usage: {psutil.cpu_percent(interval=0.1)}%",
            f"Current RAM Usage: {svmem.percent}%"
        ]
        return "\n".join(lines)

    @staticmethod
    def get_afk_info() -> str:
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except:
                pass

        time.sleep(1.0)
        processes = []
        cpu_count = psutil.cpu_count() or 1

        for process in psutil.process_iter():
            with process.oneshot():
                try:
                    pid = process.pid
                    if pid == 0: continue
                    ppid = process.ppid()
                    name = process.name()
                    create_time = datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                    cpu_usage = round(process.cpu_percent(interval=None) / cpu_count, 1)

                    try:
                        memory_usage = round(process.memory_full_info().uss / (1024 * 1024), 1)
                    except:
                        try:
                            memory_usage = round(process.memory_info().private / (1024 * 1024), 1)
                        except:
                            memory_usage = round(process.memory_info().rss / (1024 * 1024), 1)

                    status = process.status()
                    processes.append((pid, ppid, name, create_time, cpu_usage, memory_usage, status))
                except:
                    continue

        reply = "AFK Information\n" + " | ".join(str(col) for col in siconfig.AFK_COLUMNS) + "\n"
        for process in processes: reply += " | ".join(str(item) for item in process) + "\n"

        compressed = zlib.compress(reply.encode('utf-8'))
        return "AFK Information\n" + base64.b64encode(compressed).decode('utf-8')

    @staticmethod
    def get_net_connections() -> str:
        connections = []
        process_names = {p.info['pid']: p.info['name'] for p in psutil.process_iter(['pid', 'name'])}

        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                pid = conn.pid
                name = process_names.get(pid, "System/Unknown") if pid else "System/Unknown"
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
                status = conn.status
                connections.append((pid, name, laddr, raddr, status))

        reply = "Network Connections\n" + " | ".join(str(col) for col in siconfig.NET_COLUMNS) + "\n"
        for conn in connections: reply += " | ".join(str(item) for item in conn) + "\n"

        compressed = zlib.compress(reply.encode('utf-8'))
        return "Network Connections\n" + base64.b64encode(compressed).decode('utf-8')

    @staticmethod
    def get_persistence_info() -> str:
        startup_items = []
        keys_to_check = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
             r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",
             r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run")
        ]

        for hkey_root, subkey, location_name in keys_to_check:
            try:
                with winreg.OpenKey(hkey_root, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_items.append((location_name, name, value))
                            i += 1
                        except OSError:
                            break
            except:
                continue

        reply = "Persistence Information\n" + " | ".join(str(col) for col in siconfig.PERSISTENCE_COLUMNS) + "\n"
        for item in startup_items: reply += " | ".join(str(i) for i in item) + "\n"

        compressed = zlib.compress(reply.encode('utf-8'))
        return "Persistence Information\n" + base64.b64encode(compressed).decode('utf-8')

    @staticmethod
    def get_anomalies() -> str:
        anomalies = []
        sus_ports = [4444, 1337, 666, 8888, 9999, 4432]
        sus_paths = ['\\appdata\\local\\temp\\', '\\downloads\\', '\\perflogs\\']

        pid_conns = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.pid:
                    if conn.pid not in pid_conns: pid_conns[conn.pid] = []
                    pid_conns[conn.pid].append(conn)
        except:
            pass

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or "Unknown"
                exe = proc.info['exe'] or ""
                exe_lower = exe.lower()

                is_sus_path = any(p in exe_lower for p in sus_paths)
                conns = pid_conns.get(pid, [])
                has_external_conn = len(conns) > 0
                has_sus_port = any(c.raddr.port in sus_ports for c in conns)

                score = 0
                reasons = []

                if is_sus_path:
                    reasons.append("Suspicious Path (Temp/Downloads)")
                    score += 50
                if has_sus_port:
                    reasons.append("Connected to Malicious Port")
                    score += 80
                if is_sus_path and has_external_conn:
                    reasons.append("Temp Executable + Network Access")
                    score += 50

                if score > 0:
                    severity = "HIGH" if score >= 80 else ("MEDIUM" if score >= 50 else "LOW")
                    anomalies.append((pid, name, severity, " + ".join(reasons), exe))

            except:
                continue

        reply = "Anomaly Scan Results\n" + " | ".join(siconfig.ANOMALY_COLUMNS) + "\n"
        if not anomalies:
            reply += "0 | System Clean | LOW | No anomalies detected | N/A\n"
        else:
            for a in anomalies: reply += " | ".join(str(i) for i in a) + "\n"

        compressed = zlib.compress(reply.encode('utf-8'))
        return "Anomaly Scan Results\n" + base64.b64encode(compressed).decode('utf-8')

    @staticmethod
    def get_main_parent(pid):
        try:
            proc = psutil.Process(pid)
            parent = proc.parent()
            if parent and parent.name() == proc.name():
                return SystemMonitor.get_main_parent(parent.pid)
            return pid
        except:
            return pid

    @staticmethod
    def terminate_process(pid_str: str) -> str:
        parts = pid_str.split(":")
        original_pid = int(parts[0])
        kill_tree = len(parts) > 1 and parts[1] == "TREE"

        try:
            if kill_tree:
                target_pid = SystemMonitor.get_main_parent(original_pid)
                parent = psutil.Process(target_pid)
                for child in parent.children(recursive=True): child.kill()
                parent.kill()
                return f"TERMINATE Process\nSUCCESS\nTree of {target_pid}"
            else:
                psutil.Process(original_pid).kill()
                return f"TERMINATE Process\nSUCCESS\n{original_pid}"
        except:
            return "TERMINATE Process\nFAILED"

    # === הוספנו את פונקציות ההקפאה והשחרור ===
    @staticmethod
    def suspend_process(pid_str: str) -> str:
        try:
            pid = int(pid_str)
            psutil.Process(pid).suspend()
            return f"SUSPEND Process\nSUCCESS\n{pid}"
        except Exception as e:
            return f"SUSPEND Process\nFAILED\n{str(e)}"

    @staticmethod
    def resume_process(pid_str: str) -> str:
        try:
            pid = int(pid_str)
            psutil.Process(pid).resume()
            return f"RESUME Process\nSUCCESS\n{pid}"
        except Exception as e:
            return f"RESUME Process\nFAILED\n{str(e)}"


class ClientHandler(Thread):
    def __init__(self, client_socket, client_address, clients_dict):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.clients_dict = clients_dict

        self.command_map = {
            "DASHBOARD": SystemMonitor.get_dashboard_info,
            "AFKINFO": SystemMonitor.get_afk_info,
            "NETCONNS": SystemMonitor.get_net_connections,
            "PERSISTENCE": SystemMonitor.get_persistence_info,
            "SCAN_ANOMALIES": SystemMonitor.get_anomalies
        }

    def run(self):
        try:
            self.computer_name = self.client_socket.recv(siconfig.BUFSIZ).decode("utf8")
            print(f"[CONNECTED] {self.computer_name} from {self.client_address}")
            self.clients_dict[self.client_socket] = self.computer_name

            while True:
                data = self.client_socket.recv(siconfig.BUFSIZ).decode("utf8").strip()
                if not data or data == "{quit}": break

                command, param = data.split(":", 1) if ":" in data else (data, None)

                if command in self.command_map:
                    reply = self.command_map[command]()
                elif command == "TERMINATE" and param:
                    reply = SystemMonitor.terminate_process(param)
                elif command == "SUSPEND" and param:
                    reply = SystemMonitor.suspend_process(param)  # פקודה חדשה
                elif command == "RESUME" and param:
                    reply = SystemMonitor.resume_process(param)  # פקודה חדשה
                else:
                    reply = "Error: Unknown Command"

                self.client_socket.send(bytes(reply, "utf8"))

        except socket.error:
            pass
        finally:
            print(f"[DISCONNECTED] {self.computer_name}")
            self.client_socket.close()
            if self.client_socket in self.clients_dict: del self.clients_dict[self.client_socket]


class Server:
    def __init__(self, ip, port, cert_file, key_file):
        self.address = (ip, port)
        self.clients = {}
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def udp_discovery_listener(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind(('', siconfig.UDP_PORT))

        while True:
            try:
                data, addr = udp_sock.recvfrom(1024)
                if data.decode('utf-8') == siconfig.DISCOVERY_MSG:
                    udp_sock.sendto(socket.gethostname().encode('utf-8'), addr)
            except:
                pass

    def start(self):
        Thread(target=self.udp_discovery_listener, daemon=True).start()
        try:
            self.server_socket.bind(self.address)
            self.server_socket.listen(5)
            print(f"[SERVER] Running on {self.address[0]}:{self.address[1]}...")
            while True:
                client, client_address = self.server_socket.accept()
                secure_client = self.context.wrap_socket(client, server_side=True)
                ClientHandler(secure_client, client_address, self.clients).start()
        except:
            pass
        finally:
            self.server_socket.close()


if __name__ == "__main__":
    CERT_FILE = r"server.crt"
    KEY_FILE = r"server.key"
    Server(siconfig.SERVER_IP, siconfig.PORT, CERT_FILE, KEY_FILE).start()