import nmap
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
import datetime
import os

class IPScannerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("IP Scan Results")
        self.master.state('zoomed')

        self.row = 1
        self.col = 1
        self.labels = []
        self.scan_target = None  # No target by default

        self.create_widgets()

    def create_widgets(self):
        # Buttons
        self.scan_button = tk.Button(self.master, text="Start Scan", command=self.initial_scan)
        self.scan_button.grid(row=0, column=0, padx=10, pady=10, sticky='nw')

        self.new_scan_button = tk.Button(self.master, text="Find New Hosts", command=self.new_scan)
        self.new_scan_button.grid(row=0, column=1, padx=10, pady=10, sticky='nw')

        self.clear_button = tk.Button(self.master, text="Clear Labels", command=self.clear_labels)
        self.clear_button.grid(row=0, column=2, padx=10, pady=10, sticky='nw')

        self.set_target_button = tk.Button(self.master, text="Set Scan Target", command=self.set_scan_target)
        self.set_target_button.grid(row=0, column=3, padx=10, pady=10, sticky='nw')

    def clear_labels(self):
        self.clear_button.config(state=tk.DISABLED)
        for label in self.labels:
            label.destroy()
        self.labels.clear()
        self.row, self.col = 1, 1
        self.clear_button.config(state=tk.NORMAL)

    def set_scan_target(self):
        user_input = simpledialog.askstring("Scan Target", "Enter IP, multiple IPs (comma separated), or CIDR range:")
        if user_input:
            self.scan_target = user_input.strip()
            with open("ip.txt", "w") as f:
                for ip in self.scan_target.split(','):
                    f.write(ip.strip() + "\n")
            messagebox.showinfo("Target Set", f"Scan target set to: {self.scan_target}")

    def initial_scan(self):
        if not self.scan_target:
            messagebox.showwarning("No Target", "Please set a scan target first using 'Set Scan Target'.")
            return

        self.clear_labels()
        self.scan_button.config(state=tk.DISABLED)

        nm = nmap.PortScanner()

        scan_hosts = 'ip.txt' if os.path.exists('ip.txt') else self.scan_target
        if os.path.isfile(scan_hosts):
            scan_hosts = f'-iL {scan_hosts}'

        try:
            nm.scan(hosts=scan_hosts, arguments='-sn -v')
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))
            self.scan_button.config(state=tk.NORMAL)
            return

        with open("ipmac.txt", "a") as output:
            x = datetime.datetime.now()
            output.write("\nStarted Scan at " + x.strftime("%c") + "\n")
            output.write("------------------------------------------\n")
            count = 0

            for host in nm.all_hosts():
                state = nm[host].state()
                color = 'green' if state == 'up' else 'red'
                label_text = f"{host}: {'UP' if state == 'up' else 'DOWN'}"

                label = tk.Label(self.master, text=label_text, fg=color, padx=10, pady=10)
                label.grid(row=self.row, column=self.col, sticky="nsew")
                self.labels.append(label)

                self.col += 1
                if self.col > 8:
                    self.row += 1
                    self.col = 1

                mac_addr = nm[host]['addresses'].get('mac', 'MAC Address not found')
                output.write(f"{host}\t{mac_addr}\n")
                if mac_addr != 'MAC Address not found':
                    count += 1

            output.write(f"{count} hosts up\n")
            output.write("------------------------------------------\n")
            output.write("Ended Scan at " + datetime.datetime.now().strftime("%c") + "\n")

        self.scan_button.config(state=tk.NORMAL)
        self.row, self.col = 1, 1

    def new_scan(self):
        if not self.scan_target or not os.path.exists("ip.txt"):
            messagebox.showwarning("No Initial Targets", "Run an initial scan first or set scan targets.")
            return

        self.new_scan_button.config(state=tk.DISABLED)
        nm = nmap.PortScanner()

        try:
            nm.scan(hosts=self.scan_target, arguments='--min-parallelism 100 --min-rate 1000 -T3 -v -sn')
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))
            self.new_scan_button.config(state=tk.NORMAL)
            return

        existing_ips = set()
        with open("ip.txt", "r") as f:
            existing_ips = set(line.strip() for line in f if line.strip())

        new_ips = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up' and host not in existing_ips:
                new_ips.append(host)

        if new_ips:
            with open("ip.txt", "a") as output:
                for ip in new_ips:
                    output.write(f"{ip}\n")
                    print(f"New host detected: {ip}")
        else:
            print("No new hosts detected.")

        self.initial_scan()
        self.new_scan_button.config(state=tk.NORMAL)

if __name__ == '__main__':
    root = tk.Tk()
    app = IPScannerGUI(root)
    root.mainloop()
