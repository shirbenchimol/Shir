import socket
import ssl
import threading
import base64
import zlib
import sys
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

import siconfig


class NetworkManager:
    def __init__(self, on_message_received):
        self.client_socket = None
        self.is_connected = False
        self.context = ssl._create_unverified_context()
        self.on_message_received = on_message_received

    def discover_servers(self):
        discovered = {}
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.settimeout(2.0)

        try:
            udp_sock.sendto(siconfig.DISCOVERY_MSG.encode('utf-8'), ('<broadcast>', siconfig.UDP_PORT))
            while True:
                try:
                    data, addr = udp_sock.recvfrom(1024)
                    discovered[addr[0]] = data.decode('utf-8')
                except socket.timeout:
                    break
        except:
            pass
        finally:
            udp_sock.close()
        return discovered

    def connect(self, ip):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(2)
            self.client_socket = self.context.wrap_socket(raw_socket, server_hostname=ip)
            self.client_socket.connect((ip, siconfig.PORT))
            self.client_socket.settimeout(None)
            self.client_socket.send(bytes(socket.gethostname(), "utf8"))
            self.is_connected = True

            threading.Thread(target=self.receive_loop, daemon=True).start()
            return True, ""
        except Exception as e:
            return False, str(e)

    def receive_loop(self):
        while self.is_connected:
            try:
                msg = self.client_socket.recv(siconfig.BUFSIZ).decode("utf8")
                if not msg: break
                self.on_message_received(msg)
            except:
                break
        self.disconnect()

    def send_command(self, cmd):
        if self.is_connected and self.client_socket:
            try:
                self.client_socket.send(bytes(cmd, "utf8"))
            except:
                messagebox.showerror("Error", "Server connection lost!")

    def disconnect(self):
        self.is_connected = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass


class ClientGUI:
    def __init__(self):
        self.network = NetworkManager(self.handle_incoming_data)
        self.all_processes_cache = []

        while True:
            self.show_connection_window()
            if not self.network.is_connected: break
            self.show_main_window()

    def show_connection_window(self):
        self.conn_window = tk.Tk()
        self.conn_window.title("GCI Control Center")
        self.conn_window.geometry("350x300")
        self.conn_window.configure(bg="#1e1e1e")

        tk.Label(self.conn_window, text="Available Endpoints:", fg="white", bg="#1e1e1e", font=("Segoe UI", 12)).pack(
            pady=10)
        self.server_listbox = tk.Listbox(self.conn_window, width=40, height=8, bg="#2d2d2d", fg="white")
        self.server_listbox.pack(pady=5)

        btn_frame = tk.Frame(self.conn_window, bg="#1e1e1e")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Scan Network", bg="#0078D7", fg="white", relief="flat",
                  command=self.scan_network).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Connect", bg="#107C10", fg="white", relief="flat", command=self.try_connect).pack(
            side="left", padx=5)

        self.scan_network()
        self.conn_window.mainloop()

    def scan_network(self):
        self.server_listbox.delete(0, tk.END)
        self.server_listbox.insert(tk.END, "Scanning for endpoints...")
        self.conn_window.update()

        servers = self.network.discover_servers()
        self.server_listbox.delete(0, tk.END)

        if not servers:
            self.server_listbox.insert(tk.END, "Localhost (Manual) - 127.0.0.1")
        else:
            for ip, hostname in servers.items(): self.server_listbox.insert(tk.END, f"{hostname} - {ip}")

    def try_connect(self):
        selection = self.server_listbox.curselection()
        if not selection: return messagebox.showwarning("Select Server", "Please select an endpoint.")
        ip = self.server_listbox.get(selection[0]).split(" - ")[-1]

        success, err = self.network.connect(ip)
        if success:
            self.conn_window.destroy()
        else:
            messagebox.showerror("Error", f"Connection failed:\n{err}")

    def show_main_window(self):
        self.root = tk.Tk()
        self.root.title("GCI EDR Dashboard")
        self.root.geometry("950x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_hard_close)

        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(fill="x")
        tk.Button(top, text="Disconnect", bg="#D13438", fg="white", relief="flat",
                  command=self.on_disconnect_click).pack(side="right", padx=10, pady=5)

        self.tabControl = ttk.Notebook(self.root)
        self.tabControl.pack(expand=1, fill="both")

        # Tab 1: Dashboard
        self.tab_dashboard = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_dashboard, text="Dashboard")
        tk.Label(self.tab_dashboard, text="Endpoint General Information", font=("Segoe UI", 14, "bold")).pack(pady=10)
        self.dashboard_box = tk.Listbox(self.tab_dashboard, height=15, bg="#2d2d2d", fg="#00FF00",
                                        font=("Consolas", 11))
        self.dashboard_box.pack(padx=10, pady=10, expand=True, fill="both")
        tk.Button(self.tab_dashboard, text="Refresh", bg="#0078D7", fg="white",
                  command=lambda: self.network.send_command("DASHBOARD")).pack(pady=10)

        # Tab 2: Process Explorer (הוספנו לפה את הכפתורים החדשים)
        self.tab_afk = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_afk, text="Process Explorer")
        sf = tk.Frame(self.tab_afk)
        sf.pack(fill="x", padx=10, pady=5)
        tk.Label(sf, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.update_search)
        tk.Entry(sf, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=5)

        self.afk_info_box = ttk.Treeview(self.tab_afk, columns=siconfig.AFK_COLUMNS, show="tree headings", height=15)
        self.afk_info_box.heading("#0", text="")
        self.afk_info_box.column("#0", width=40, stretch=tk.NO)

        for col in siconfig.AFK_COLUMNS:
            self.afk_info_box.heading(col, text=col)
            self.afk_info_box.column(col, anchor="center", width=120)

        self.afk_info_box.pack(padx=10, pady=10, expand=True, fill="both")

        bf = tk.Frame(self.tab_afk)
        bf.pack(pady=10)
        tk.Button(bf, text="Refresh", bg="#5C2D91", fg="white",
                  command=lambda: self.network.send_command("AFKINFO")).pack(side="left", padx=5)
        tk.Button(bf, text="RESUME", bg="#107C10", fg="white", command=self.resume_action).pack(side="left", padx=5)
        tk.Button(bf, text="SUSPEND", bg="#FFB900", fg="black", command=self.suspend_action).pack(side="left", padx=5)
        tk.Button(bf, text="TERMINATE", bg="#D13438", fg="white", command=self.terminate_action).pack(side="left",
                                                                                                      padx=5)

        # Tab 3: Live Connections
        self.tab_net = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_net, text="Live Connections")
        self.net_info_box = ttk.Treeview(self.tab_net, columns=siconfig.NET_COLUMNS, show="headings", height=15)
        for col in siconfig.NET_COLUMNS: self.net_info_box.heading(col, text=col); self.net_info_box.column(col,
                                                                                                            anchor="center")
        self.net_info_box.pack(padx=10, pady=10, expand=True, fill="both")
        tk.Button(self.tab_net, text="Refresh Connections", bg="#D83B01", fg="white",
                  command=lambda: self.network.send_command("NETCONNS")).pack(pady=10)

        # Tab 4: Persistence
        self.tab_persistence = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_persistence, text="Startup Persistence")
        self.pers_info_box = ttk.Treeview(self.tab_persistence, columns=siconfig.PERSISTENCE_COLUMNS, show="headings",
                                          height=15)

        self.pers_info_box.heading(siconfig.PERSISTENCE_COLUMNS[0], text=siconfig.PERSISTENCE_COLUMNS[0])
        self.pers_info_box.column(siconfig.PERSISTENCE_COLUMNS[0], anchor="w", width=350)
        self.pers_info_box.heading(siconfig.PERSISTENCE_COLUMNS[1], text=siconfig.PERSISTENCE_COLUMNS[1])
        self.pers_info_box.column(siconfig.PERSISTENCE_COLUMNS[1], anchor="w", width=150)
        self.pers_info_box.heading(siconfig.PERSISTENCE_COLUMNS[2], text=siconfig.PERSISTENCE_COLUMNS[2])
        self.pers_info_box.column(siconfig.PERSISTENCE_COLUMNS[2], anchor="w", width=400)

        self.pers_info_box.pack(padx=10, pady=10, expand=True, fill="both")
        tk.Button(self.tab_persistence, text="Scan Persistence", bg="#107C10", fg="white",
                  command=lambda: self.network.send_command("PERSISTENCE")).pack(pady=10)

        # Tab 5: Threat Hunter
        self.tab_anomaly = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_anomaly, text="Threat Hunter")
        tk.Label(self.tab_anomaly, text="Heuristic Anomaly Detection Engine", font=("Segoe UI", 12, "bold"),
                 fg="#D13438").pack(pady=5)

        self.anomaly_info_box = ttk.Treeview(self.tab_anomaly, columns=siconfig.ANOMALY_COLUMNS, show="headings",
                                             height=15)
        self.anomaly_info_box.tag_configure('HIGH', background='#ffcccc', foreground='black')
        self.anomaly_info_box.tag_configure('MEDIUM', background='#ffe6cc', foreground='black')
        self.anomaly_info_box.tag_configure('LOW', background='#e6ffe6', foreground='black')

        for col in siconfig.ANOMALY_COLUMNS:
            self.anomaly_info_box.heading(col, text=col)
            self.anomaly_info_box.column(col, anchor="w", width=150 if col != "Execution Path" else 400)

        self.anomaly_info_box.pack(padx=10, pady=10, expand=True, fill="both")
        tk.Button(self.tab_anomaly, text="Run Heuristic Scan", bg="#000000", fg="#00FF00",
                  font=("Consolas", 10, "bold"), command=lambda: self.network.send_command("SCAN_ANOMALIES")).pack(
            pady=5)
        tk.Button(self.tab_anomaly, text="Export Scan Report", bg="#107C10", fg="white", font=("Consolas", 10, "bold"),
                  command=self.export_report).pack(pady=5)

        self.network.send_command("DASHBOARD")
        self.root.mainloop()

    def handle_incoming_data(self, msg):
        lines = msg.split("\n")
        header = lines[0]

        if header == "Dashboard Info":
            self.dashboard_box.delete(0, tk.END)
            for line in lines[1:]: self.dashboard_box.insert(tk.END, "  " + line)
        elif header == "AFK Information":
            self.update_afk_cache(lines[1])
        elif header == "Network Connections":
            self.update_cache_and_tree(lines[1], self.net_info_box)
        elif header == "Persistence Information":
            self.update_cache_and_tree(lines[1], self.pers_info_box)
        elif header == "Anomaly Scan Results":
            self.update_anomalies(lines[1])
        elif header == "TERMINATE Process":
            if "SUCCESS" in lines:
                messagebox.showinfo("Success", "Termination Successful!")
            else:
                messagebox.showerror("Error", "Termination Failed")
            self.network.send_command("AFKINFO")
        # טיפול בהודעות החזרה של השהיה ושחרור
        elif header == "SUSPEND Process":
            if "SUCCESS" in lines:
                messagebox.showinfo("Success", "Process Suspended (Frozen) Successfully!")
            else:
                messagebox.showerror("Error", f"Suspend Failed:\n{lines[-1]}")
            self.network.send_command("AFKINFO")
        elif header == "RESUME Process":
            if "SUCCESS" in lines:
                messagebox.showinfo("Success", "Process Resumed Successfully!")
            else:
                messagebox.showerror("Error", f"Resume Failed:\n{lines[-1]}")
            self.network.send_command("AFKINFO")

    def update_cache_and_tree(self, encoded_data, tree):
        try:
            decoded_data = zlib.decompress(base64.b64decode(encoded_data)).decode('utf-8')
            items = [line.split(" | ") for line in decoded_data.split("\n")[2:] if " | " in line]
            for item in tree.get_children(): tree.delete(item)
            for i in items: tree.insert("", "end", values=i)
        except:
            pass

    def update_afk_cache(self, encoded_data):
        try:
            decoded_data = zlib.decompress(base64.b64decode(encoded_data)).decode('utf-8')
            self.all_processes_cache = [line.split(" | ") for line in decoded_data.split("\n")[2:] if " | " in line]
            self.update_search()
        except:
            pass

    def update_search(self, *args):
        query = self.search_var.get().lower()
        for item in self.afk_info_box.get_children(): self.afk_info_box.delete(item)

        inserted_pids = {}
        for p in self.all_processes_cache:
            pid, ppid, name = p[0], p[1], p[2]
            if query and query not in str(pid).lower() and query not in str(name).lower():
                continue
            try:
                self.afk_info_box.insert("", "end", iid=pid, values=p)
                inserted_pids[pid] = ppid
            except:
                pass

        if not query:
            for pid, ppid in inserted_pids.items():
                if ppid in inserted_pids:
                    try:
                        self.afk_info_box.move(pid, ppid, 'end')
                    except:
                        pass

    def update_anomalies(self, encoded_data):
        try:
            decoded_data = zlib.decompress(base64.b64decode(encoded_data)).decode('utf-8')
            items = [line.split(" | ") for line in decoded_data.split("\n")[2:] if " | " in line]
            for item in self.anomaly_info_box.get_children(): self.anomaly_info_box.delete(item)
            for i in items:
                severity = i[2]
                self.anomaly_info_box.insert("", "end", values=i, tags=(severity,))
        except:
            pass

    def export_report(self):
        items = self.anomaly_info_box.get_children()
        if not items:
            messagebox.showwarning("Empty Report", "No scan results to export. Please run a scan first.")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"Threat_Report_{timestamp}.txt"

        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write("=== GCI EDR Threat Hunter Report ===\n")
                file.write(f"Scan Date & Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write("-" * 120 + "\n")
                file.write(" | ".join(siconfig.ANOMALY_COLUMNS) + "\n")
                file.write("-" * 120 + "\n")

                for item in items:
                    values = self.anomaly_info_box.item(item, "values")
                    file.write(" | ".join(str(v) for v in values) + "\n")

            filepath = os.path.abspath(filename)
            messagebox.showinfo("Export Successful", f"Report saved successfully!\nLocation: {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save report:\n{e}")

    # === פונקציות הכפתורים החדשים ===
    def suspend_action(self):
        selected = self.afk_info_box.selection()
        if not selected: return messagebox.showwarning("Warning", "Select a process to suspend!")
        values = self.afk_info_box.item(selected[0], 'values')
        pid, name = values[0], values[2]

        ans = messagebox.askyesno("Suspend", f"Are you sure you want to FREEZE {name} (PID: {pid})?")
        if ans: self.network.send_command(f"SUSPEND:{pid}")

    def resume_action(self):
        selected = self.afk_info_box.selection()
        if not selected: return messagebox.showwarning("Warning", "Select a process to resume!")
        values = self.afk_info_box.item(selected[0], 'values')
        pid, name = values[0], values[2]

        ans = messagebox.askyesno("Resume", f"Are you sure you want to UNFREEZE {name} (PID: {pid})?")
        if ans: self.network.send_command(f"RESUME:{pid}")

    def terminate_action(self):
        selected = self.afk_info_box.selection()
        if not selected: return messagebox.showwarning("Warning", "Select a process!")
        values = self.afk_info_box.item(selected[0], 'values')
        pid, name = values[0], values[2]

        ans = messagebox.askyesnocancel("Terminate",
                                        f"{name} (PID: {pid})\nYES: Close App Tree\nNO: Close this Process\nCANCEL: Abort")
        if ans is True:
            self.network.send_command(f"TERMINATE:{pid}:TREE")
        elif ans is False:
            self.network.send_command(f"TERMINATE:{pid}")

    def on_disconnect_click(self):
        self.network.send_command("{quit}");
        self.network.disconnect();
        self.root.destroy()

    def on_hard_close(self):
        self.network.send_command("{quit}");
        self.network.disconnect();
        self.root.destroy();
        sys.exit()


if __name__ == "__main__":
    ClientGUI()
