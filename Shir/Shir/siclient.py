import socket
import ssl
import threading
import base64
import zlib
import sys
import tkinter as tk
import os
from datetime import datetime
from tkinter import ttk, messagebox

import siconfig


# מחלקה שמטפלת בכל התקשורת עם השרת
# חיבור קבלת נתונים ושליחת פקודות
class NetworkManager:
    def __init__(self, on_message_received):
        self.client_socket = None
        self.is_connected = False
        self.context = ssl._create_unverified_context()
        self.on_message_received = on_message_received

    # מחפש שרתים ברשת המקומית בעזרת שידור UDP
    def discover_servers(self):
        discovered = {}
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.settimeout(2.0)

        try:
            udp_sock.sendto(
                siconfig.DISCOVERY_MSG.encode('utf-8'),
                ('<broadcast>', siconfig.UDP_PORT)
            )

            # מקבל תשובות עד שנגמר הזמן
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

    # מתחבר לשרת לפי כתובת ip
    def connect(self, ip):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(2)

            self.client_socket = self.context.wrap_socket(
                raw_socket,
                server_hostname=ip
            )

            self.client_socket.connect((ip, siconfig.PORT))
            self.client_socket.settimeout(None)

            # שולח את שם המחשב כדי שהשרת יזהה מי התחבר
            self.client_socket.send(bytes(socket.gethostname(), "utf8"))

            self.is_connected = True

            # מפעיל חוט שמאזין להודעות מהשרת
            threading.Thread(target=self.receive_loop, daemon=True).start()

            return True, ""
        except Exception as e:
            return False, str(e)

    # לולאה שמקבלת הודעות כל הזמן מהשרת
    def receive_loop(self):
        while self.is_connected:
            try:
                msg = self.client_socket.recv(siconfig.BUFSIZ).decode("utf8")
                if not msg:
                    break

                # מעביר את ההודעה לממשק המשתמש
                self.on_message_received(msg)

            except:
                break

        self.disconnect()

    # שליחת פקודה לשרת
    def send_command(self, cmd):
        if self.is_connected and self.client_socket:
            try:
                self.client_socket.send(bytes(cmd, "utf8"))
            except:
                messagebox.showerror("Error", "Server connection lost")

    # ניתוק מהשרת וניקוי החיבור
    def disconnect(self):
        self.is_connected = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass


# מחלקה של הממשק הגרפי
# כאן מוצג כל המידע למשתמש
class ClientGUI:
    def __init__(self):
        self.network = NetworkManager(self.handle_incoming_data)

        # שומר רשימה של תהליכים לחיפוש
        self.all_processes_cache = []

        # כל פעם פותח חלון התחברות ואז חלון ראשי
        while True:
            self.show_connection_window()
            if not self.network.is_connected:
                break
            self.show_main_window()

    # חלון שמראה שרתים שאפשר להתחבר אליהם
    def show_connection_window(self):
        self.conn_window = tk.Tk()
        self.conn_window.title("Control Center")
        self.conn_window.geometry("350x300")
        self.conn_window.configure(bg="#1e1e1e")

        tk.Label(
            self.conn_window,
            text="Available Servers",
            fg="white",
            bg="#1e1e1e",
            font=("Segoe UI", 12)
        ).pack(pady=10)

        self.server_listbox = tk.Listbox(
            self.conn_window,
            width=40,
            height=8,
            bg="#2d2d2d",
            fg="white"
        )
        self.server_listbox.pack(pady=5)

        btn_frame = tk.Frame(self.conn_window, bg="#1e1e1e")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Scan", command=self.scan_network).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Connect", command=self.try_connect).pack(side="left", padx=5)

        self.scan_network()
        self.conn_window.mainloop()

    # מחפש שרתים ברשת ומציג אותם
    def scan_network(self):
        self.server_listbox.delete(0, tk.END)
        self.server_listbox.insert(tk.END, "Scanning...")
        self.conn_window.update()

        servers = self.network.discover_servers()
        self.server_listbox.delete(0, tk.END)

        if not servers:
            self.server_listbox.insert(tk.END, "Localhost 127.0.0.1")
        else:
            for ip, hostname in servers.items():
                self.server_listbox.insert(tk.END, f"{hostname} {ip}")

    # מנסה להתחבר לשרת שנבחר
    def try_connect(self):
        selection = self.server_listbox.curselection()
        if not selection:
            return messagebox.showwarning("Select", "Please choose a server")

        ip = self.server_listbox.get(selection[0]).split()[-1]

        success, err = self.network.connect(ip)
        if success:
            self.conn_window.destroy()
        else:
            messagebox.showerror("Error", err)

    # חלון ראשי שבו רואים את כל הנתונים
    def show_main_window(self):
        self.root = tk.Tk()
        self.root.title("Dashboard")
        self.root.geometry("950x700")

        self.tabControl = ttk.Notebook(self.root)
        self.tabControl.pack(expand=1, fill="both")

        self.tab_dashboard = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_dashboard, text="Dashboard")

        self.dashboard_box = tk.Listbox(self.tab_dashboard)
        self.dashboard_box.pack(expand=True, fill="both")

        tk.Button(
            self.tab_dashboard,
            text="Refresh",
            command=lambda: self.network.send_command("DASHBOARD")
        ).pack()

        self.tab_afk = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_afk, text="Processes")

        self.afk_info_box = ttk.Treeview(self.tab_afk, show="headings")
        self.afk_info_box.pack(expand=True, fill="both")

        tk.Button(self.tab_afk, text="Refresh",
                  command=lambda: self.network.send_command("AFKINFO")).pack()

        tk.Button(self.tab_afk, text="Suspend", command=self.suspend_action).pack()
        tk.Button(self.tab_afk, text="Resume", command=self.resume_action).pack()
        tk.Button(self.tab_afk, text="Terminate", command=self.terminate_action).pack()

        self.network.send_command("DASHBOARD")

        self.root.mainloop()

    # מקבל הודעות מהשרת ומחליט לאן להכניס אותן
    def handle_incoming_data(self, msg):
        lines = msg.split("\n")
        header = lines[0]

        if header == "Dashboard Info":
            self.dashboard_box.delete(0, tk.END)
            for line in lines[1:]:
                self.dashboard_box.insert(tk.END, line)

        elif header == "AFK Information":
            self.update_afk_cache(lines[1])

    # פענוח נתונים דחוסים
    def update_afk_cache(self, encoded_data):
        try:
            decoded = zlib.decompress(base64.b64decode(encoded_data)).decode("utf-8")
            self.all_processes_cache = decoded.split("\n")
        except:
            pass

    def suspend_action(self):
        pass

    def resume_action(self):
        pass

    def terminate_action(self):
        pass

    # התנתקות
    def on_disconnect_click(self):
        self.network.send_command("{quit}")
        self.network.disconnect()
        self.root.destroy()

    def on_hard_close(self):
        self.on_disconnect_click()
        sys.exit()


if __name__ == "__main__":
    ClientGUI()
