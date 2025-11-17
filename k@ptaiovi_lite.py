#!/usr/bin/env python3
# kaptainovi_lite.py - Phase 1 core (nano-safe, iSH-friendly)
# Offline-first Kaptainovi Lite: phone lookup, IP recon, report search, logging.

import os
import sys
import time
import socket
import json
import subprocess
import ssl
import smtplib
import http.client
import urllib.parse
from urllib.parse import urlparse
from datetime import datetime

# --- Simple Progress Bar ---
def progress_bar(task="Processing", duration=3):
    """Simple progress bar for visual feedback."""
    length = 30  # bar length in characters
    print(f"{task}: ", end="", flush=True)
    for i in range(length + 1):
        percent = int((i / length) * 100)
        bar = "#" * i + "-" * (length - i)
        sys.stdout.write(f"\r{task}: [{bar}] {percent}%")
        sys.stdout.flush()
        time.sleep(duration / length)
    print("\n" + G + "Done!" + RST)

# --- Base Colors (keep these if already present) ---
RST = "\033[0m"      # Reset
R = "\033[31m"       # Red (basic)
G = "\033[32m"       # Green
Y = "\033[33m"       # Yellow
B = "\033[34m"       # Blue
C = "\033[36m"       # Cyan
W = "\033[97m"       # Bright White
M = "\033[35m"       # Magenta

# --- Extended Colors (paste these right after the base colors) ---
PURPLE = "\033[38;5;93m"     # Purple
GOLD   = "\033[38;5;220m"    # Gold / Yellow-Orange
BRIGHT_RED = "\033[38;5;196m"# Bright Red (more punchy than R)
TEAL   = "\033[38;5;45m"     # Teal / Aqua
PINK   = "\033[38;5;205m"    # Pink
ORANGE = "\033[38;5;208m"    # Orange

# Optional convenience map if you want to reference colors by name later:
COLOR_MAP = {
    "reset": RST, "red": R, "bright_red": BRIGHT_RED, "green": G, "yellow": Y,
    "blue": B, "cyan": C, "white": W, "magenta": M,
    "purple": PURPLE, "gold": GOLD, "teal": TEAL, "pink": PINK, "orange": ORANGE
}

def tie_dye(text):
    """Render text in alternating tie-dye pink, blue, and white colors."""
    colors = ["\033[38;5;205m", "\033[38;5;39m", "\033[97m"]  # Pink, Blue, White
    result = ""
    for i, char in enumerate(text):
        result += colors[i % len(colors)] + char
    result += "\033[0m"  # Reset at end
    return result

HOME = os.path.expanduser("~")
REPORTS_DIR = os.path.join(HOME, "Kaptainovi", "Reports")
LOG_DIR = os.path.join(HOME, ".kaptainovi_logs")
LOG_FILE = os.path.join(LOG_DIR, "kaptainovi.log")

# ensure dirs
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# small country code hints for phone lookup (expandable)
COUNTRY_CODES = {
    "1": "United States/Canada (+1)",
    "44": "United Kingdom (+44)",
    "61": "Australia (+61)",
    "91": "India (+91)",
    "49": "Germany (+49)",
    "33": "France (+33)",
    "81": "Japan (+81)",
    "39": "Italy (+39)"
}

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,3306,3389,5900,8080]

def log(msg):
    ts = datetime.utcnow().isoformat()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(ts + " " + msg + "\n")
    except:
        pass

def header(title="KAPTAINOVI - LITE"):
    os.system("clear")
    print(G + B + "== " + title + " ==" + RST)
    print("Authorized use only. Use on assets you own or have permission to test.")
    print("Time (UTC):", datetime.utcnow().isoformat())
    print("-" * 48)

def pause():
    input("\nPress Enter to continue...")

# ---------------- Phone lookup ----------------
def phone_lookup_flow(learning):
    """
    Phone lookup + consent-based IP capture (local). iSH-safe, uses Python stdlib HTTP server.
    Replaces old phone_lookup_flow. Saves reports to REPORTS_DIR/<phone>/.
    """
    import threading, http.server, socketserver, secrets, socket, urllib.parse, json, sys

    if learning:
        print(Y + "Learning: Phone lookup will format numbers and can optionally capture a consenting device's public IP." + RST)
        time.sleep(1)

    num = input("Enter phone number (international or national): ").strip()
    digits = "".join(c for c in num if c.isdigit())
    if not digits:
        print(R + "No digits found." + RST)
        log("PHONE lookup failed - no digits")
        return

    # basic offline formatting & country hint
    country_hint = "Unknown"
    national = digits
    for L in (3,2,1):
        if len(digits) > L:
            code = digits[:L]
            if code in COUNTRY_CODES:
                country_hint = COUNTRY_CODES[code]
                national = digits[L:]
                break

    # show basic result & save report
    print("\nRaw input:", num)
    print("Digits only:", digits)
    print("Country hint:", country_hint)
    print("National number (approx):", national)
    print("Length:", len(digits))

    target = "phone_" + digits
    rdir = os.path.join(REPORTS_DIR, target)
    os.makedirs(rdir, exist_ok=True)

    report = {
        "query": num,
        "digits": digits,
        "country_hint": country_hint,
        "national": national,
        "timestamp": datetime.utcnow().isoformat()
    }
    with open(os.path.join(rdir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(rdir, "report.txt"), "w") as f:
        f.write("PHONE REPORT\n")
        f.write(json.dumps(report, indent=2))

    print(G + "Saved basic phone report to: " + rdir + RST)
    log("PHONE lookup " + digits)

    # --- Offer consent-based IP capture ---
    print("")
    print(Y + "Optional: Capture consenting device IP (works on same Wi-Fi / LAN)." + RST)
    print("  This requires the target to open a short link in their browser.")
    print("  Remote capture (over Internet) requires port-forwarding or a publicly routable server.")
    choice = input("Do you want to attempt a consent-based IP capture now? (y/N): ").strip().lower()
    if choice != "y":
        return

    # Permission check
    agree = input(R + "Type 'I HAVE PERMISSION' to confirm you have explicit consent to capture this device's IP: " + RST).strip()
    if agree.lower() != "i have permission":
        print(R + "Permission not confirmed -aborting capture." + RST)
        log("PHONE capture aborted - no permission")
        return

    # Start tiny HTTP server and wait for single hit
    # Get local IP (best-effort)
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # doesn't need to be reachable; Google's IP used only to pick interface
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    local_ip = get_local_ip()
    default_port = 9000
    port_input = input(f"Port to listen on [{default_port}] (ensure firewall/router allows it for remote capture): ").strip()
    try:
        port = int(port_input) if port_input else default_port
    except:
        port = default_port

    token = secrets.token_urlsafe(6)
    path_token = f"/track/{token}"

    # shared state
    captured = {"hit": False, "client_ip": None, "headers": None, "ua": None, "timestamp": None, "query": None}

    class OneShotHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != path_token:
                # respond with simple page
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Not found")
                return
            # Record client info
            client_ip = self.client_address[0]
            ua = self.headers.get("User-Agent", "")
            qs = urllib.parse.parse_qs(parsed.query)
            captured["hit"] = True
            captured["client_ip"] = client_ip
            captured["headers"] = dict(self.headers)
            captured["ua"] = ua
            captured["timestamp"] = datetime.utcnow().isoformat()
            captured["query"] = {k: v for k, v in qs.items()}

            # respond politely and show confirmation (so consenting user sees it worked)
            resp = ("Thanks - your device IP has been logged with permission. You may close this page.\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            try:
                self.wfile.write(resp)
            except:
                pass
            # stop server by shutting down in a separate thread to avoid deadlock
            def shutdown_later(server=self.server):
                try:
                    server.shutdown()
                except:
                    pass
            threading.Thread(target=shutdown_later, daemon=True).start()

        # silence logging to avoid noisy output
        def log_message(self, format, *args):
            return

    # Start server in a thread
    try:
        httpd = socketserver.TCPServer(("", port), OneShotHandler)
    except Exception as e:
        print(R + f"Failed to bind to port {port}: {e}" + RST)
        log(f"PHONE capture bind fail {port} {e}")
        return

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    # Provide user with link to share with consenting target
    local_url = f"http://{local_ip}:{port}{path_token}"
    print(G + "\nTracking URL (local LAN): " + RST + local_url)
    print(Y + "If the target is on the same Wi-Fi, ask them to open that link in their browser now." + RST)
    print(Y + "If the target is remote, you must expose this machine to the Internet (port-forward) or host on a public server." + RST)
    print(Y + "Waiting for the consenting device to open the link (timeout 300s)..." + RST)

    # Wait for a hit (max timeout)
    timeout = 300  # seconds (5 minutes)
    start = time.time()
    while not captured["hit"] and (time.time() - start) < timeout:
        time.sleep(0.5)

    # Shut down server if still running
    try:
        httpd.shutdown()
        httpd.server_close()
    except:
        pass

    if not captured["hit"]:
        print(R + "\nNo hit received within timeout. Capture failed or target did not open the link." + RST)
        log("PHONE capture timeout " + digits)
        return

    # Save capture report
    cap_report = {
        "phone_query": num, "digits": digits,
        "captured_ip": captured["client_ip"],
        "user_agent": captured["ua"],
        "headers": captured["headers"],
        "timestamp": captured["timestamp"],
        "note": "Consent-based capture; operator confirmed permission prior to capture."
    }
    try:
        with open(os.path.join(rdir, "ip_capture.json"), "w") as f:
            json.dump(cap_report, f, indent=2)
        with open(os.path.join(rdir, "ip_capture.txt"), "w") as f:
            f.write("IP CAPTURE REPORT\n")
            f.write(json.dumps(cap_report, indent=2))
        print(G + "\nCaptured IP and saved report to: " + rdir + RST)
        print(G + f"Captured IP: {captured['client_ip']}  (User-Agent: {captured['ua']})" + RST)
        log("PHONE capture success " + digits + " -> " + captured["client_ip"])
    except Exception as e:
        print(R + "Failed to save capture report: " + str(e) + RST)
        log("PHONE capture save fail " + str(e))

#-----------------------------------------------------------------------------------------

#-------------------------------------Network_Scan_advanced---------------------------------------

def new_network_scan_flow(subnet="10.0.0.0/24"):
    import subprocess
    import socket
    import requests
    from scapy.all import ARP, Ether, srp

    # --- Vendor lookup function ---
    def get_vendor(mac):
        oui = mac.upper()[0:8].replace(":", "-")
        try:
            r = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
            return r.text
        except:
            return "Unknown vendor"

    print(f"\nScanning network: {subnet}")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc

        # Hostname lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "unknown"

        # Vendor lookup
        vendor = get_vendor(mac)

        devices.append((ip, mac, hostname, vendor))

    # Print table
    print("\nIdentified devices:")
    print("{:<15} {:<20} {:<30} {:<25}".format("IP Address", "MAC Address", "Hostname", "Vendor"))
    for ip, mac, hostname, vendor in devices:
        print("{:<15} {:<20} {:<30} {:<25}".format(ip, mac, hostname, vendor))

    # --- Save network scan report ---
    from datetime import datetime
    import os
    import json
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Directories
    scan_dir = os.path.join(REPORTS_DIR, "network_scan")
    os.makedirs(scan_dir, exist_ok=True)

    json_path = os.path.join(scan_dir, f"scan_{timestamp}.json")
    txt_path = os.path.join(scan_dir, f"scan_{timestamp}.txt")
    alert_path = os.path.join(scan_dir, f"scan_{timestamp}_alerts.txt")

    # Current scan as JSON
    json_report = {
        "timestamp": timestamp,
        "subnet": subnet,
        "device_count": len(devices),
        "devices": [
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor
            }
            for (ip, mac, hostname, vendor) in devices
        ]
    }

    # -----------------------------------------
    # 🔥 NEW DEVICE DETECTION
    # -----------------------------------------
    previous_devices = {}

    # load the most recent previous scan if exists
    try:
        scans = [f for f in os.listdir(scan_dir) if f.endswith(".json")]
        scans.sort()
        if scans:
            last_scan = scans[-1]  # newest
            with open(os.path.join(scan_dir, last_scan), "r") as f:
                prev_data = json.load(f)
                for dev in prev_data["devices"]:
                    previous_devices[dev["mac"]] = dev
    except:
        previous_devices = {}

    # Compare lists
    new_devices = []
    for (ip, mac, hostname, vendor) in devices:
        if mac not in previous_devices:
            new_devices.append((ip, mac, hostname, vendor))

    # Print alerts
    if new_devices:
        print("\n" + Y + "⚠ NEW DEVICES DETECTED ON NETWORK ⚠" + RST)
        for ip, mac, hostname, vendor in new_devices:
            print(f"{G}NEW DEVICE: {ip} | {mac} | {hostname} | {vendor}{RST}")
    else:
        print(G + "\nNo new devices detected since last scan." + RST)

    # Save alerts to file
    with open(alert_path, "w") as f:
        if new_devices:
            f.write("NEW DEVICES DETECTED:\n\n")
            for ip, mac, hostname, vendor in new_devices:
                f.write(f"{ip}  {mac}  {hostname}  {vendor}\n")
        else:
            f.write("No new devices detected.\n")

    # -----------------------------------------

    # Save JSON report
    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2)

    # Save TXT report
    with open(txt_path, "w") as f:
        f.write("NETWORK SCAN REPORT\n")
        f.write(f"Subnet: {subnet}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Devices Found: {len(devices)}\n\n")
        f.write("{:<15} {:<20} {:<30} {:<25}\n".format(
            "IP Address", "MAC Address", "Hostname", "Vendor"
        ))
        f.write("-" * 95 + "\n")
        for ip, mac, hostname, vendor in devices:
            f.write("{:<15} {:<20} {:<30} {:<25}\n".format(ip, mac, hostname, vendor))

    print(G + f"\nSaved network scan and alert report to: {scan_dir}" + RST)

    return devices


#---------------------------------------------------------------------------------------------
            

#--------------------------Name / Email search ----------------
def search_reports_flow(learning):
    if learning:
        print(Y + "Learning: this searches saved reports for the string you provide." + RST)
        time.sleep(1)
    term = input("Enter name or email to search reports: ").strip().lower()
    if not term:
        print("No search term.")
        return

    progress_bar("looking for the email relax", duration=5)

    matches = []
    for root,dirs,files in os.walk(REPORTS_DIR):
        for fn in files:
            if fn.endswith(".txt") or fn.endswith(".json"):
                path = os.path.join(root, fn)
                try:
                    with open(path, "r", errors="ignore") as f:
                        txt = f.read().lower()
                        if term in txt:
                            matches.append(path)
                except:
                    pass
    if not matches:
        
        print(R + "No matches found in reports." + RST)
    else:
        print(G + "Matches found:" + RST)
        for m in matches:
            print(" -", m)
    log("SEARCH reports term=" + term)

# ---------------- IP / Host recon ----------------
def port_probe(host, ports, timeout=1.5):
    results = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            results[p] = True
            s.close()
        except:
            results[p] = False
    return results

def banner_grab(host, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            data = s.recv(512)
        except:
            data = b""
        s.close()
        if not data:
            return ""
        return data.decode(errors="ignore").splitlines()[:6]
    except:
        return ""

def ip_recon_flow(learning):
    if learning:
        print(Y + "Learning: IP recon resolves host, probes ports and reads small banners." + RST)
        print("Banner grabs are small reads only - no payloads are sent.")
        time.sleep(1)
    target = input("Enter IP or hostname: ").strip()
    if not target:
        print("No target.")
        return
    progress_bar("snatching IP baby boy we moving", duration=8.25)
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = None
    rev = None
    if ip:
        try:
            rev = socket.gethostbyaddr(ip)[0]
        except:
            rev = None
    print("Target:", target)
    print("Resolved IP:", ip or "N/A")
    print("Reverse DNS:", rev or "N/A")
    ports_input = input("Ports to probe (comma) [default common]: ").strip()
    if not ports_input:
        ports = COMMON_PORTS if 'COMMON_PORTS' in globals() else [22,80,443]
    else:
        ports = []
    for p in ports_input.split(","):
            try:
                ports.append(int(p.strip()))
            except:
                pass
    print("Probing ports:", ports)
    res = port_probe(ip or target, ports)
    report = {
       "target": target,
        "resolved_ip": ip,
        "reverse_dns": rev,
        "ports": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    progress_bar("ports open for shipping", duration=7.5)
    for p,openstate in res.items():
        report["ports"][str(p)] = {"open": openstate}
        if openstate:
            banner = banner_grab(ip or target, p)
            if banner:
                report["ports"][str(p)]["banner"] = banner
    safe_name = (ip or target).replace(":", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(rdir, "report.txt"), "w") as f:
        f.write("IP RECON REPORT\n")
        f.write(json.dumps(report, indent=2))
    print(G + "Saved report to: " + rdir + RST)
    log("IPRECON " + str(target))

# ---------------- Smart Recon (banner analysis) ----------------
import re

SMART_PORTS = [22,80,443,25,110,143,3306,8080]

def analyze_banner_lines(lines):
    """Lightweight heuristics to guess service and OS from banner lines."""
    service = "unknown"
    os_hint = "unknown"
    for ln in lines:
        l = ln.lower()
        # service hints
        if "nginx" in l: service = "nginx"
        if "apache" in l: service = "apache"
        if "iis" in l or "microsoft-iis" in l: service = "iis"
        if "ssh" in l or "openssh" in l: service = "ssh"
        if "mysql" in l: service = "mysql"
        if "postgres" in l: service = "postgres"
        # os hints by common strings
        if "ubuntu" in l or "debian" in l: os_hint = "Linux (Debian/Ubuntu)"
        if "centos" in l or "red hat" in l: os_hint = "Linux (CentOS/RedHat)"
        if "windows" in l or "iis" in l: os_hint = "Windows"
        if "darwin" in l or "apple" in l: os_hint = "macOS"
    return service, os_hint

def smart_recon_flow(learning):
    """Smart Recon: multiple banner grabs + analysis."""
    if learning:
        print(Y + "Learning: Smart Recon will grab small banners from common ports" + RST)
        print("It will NOT attempt logins or exploits. It only reads initial text returned by services.")
        time.sleep(1)
    target = input("Enter hostname or IP for Smart Recon: ").strip()
    if not target:
        print(R + "No target provided." + RST); return

    progress_bar("Running Smart Recon", duration=5)
     
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = None
    print("Target:", target, "Resolved IP:", ip or "N/A")
    recon = {"target": target, "ip": ip, "banners": {}, "analysis": {}, "timestamp": datetime.utcnow().isoformat()}
    for p in SMART_PORTS:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip or target, p))
            try:
                data = s.recv(512)
            except:
                data = b""
            s.close()

            progress_bar("Analyzing Banners", duration=4)
            
            lines = [ln for ln in data.decode(errors="ignore").splitlines() if ln.strip()]
            if lines:
                recon["banners"][str(p)] = lines
                svc, osh = analyze_banner_lines(lines)
                recon["analysis"][str(p)] = {"service_hint": svc, "os_hint": osh}
                print(G + f"[{p}] banner found ({svc}/{osh})" + RST)
            else:
                print(R + f"[{p}] no banner" + RST)
        except Exception:
            # silent skip
            pass
    # save report
    safe_name = (ip or target).replace(":", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "smart_recon.json"), "w") as f:
        json.dump(recon, f, indent=2)
    with open(os.path.join(rdir, "smart_recon.txt"), "w") as f:
        f.write("SMART RECON REPORT\n")
        f.write(json.dumps(recon, indent=2))
    print(G + "Saved Smart Recon report to: " + rdir + RST)
    log("SMARTRECON " + str(target))

# ---------------- Trace & Map (best-effort traceroute) ----------------
import subprocess

def trace_map_flow(learning):
    if learning:
        print(Y + "Learning: Trace & Map will try to run system traceroute (if installed)." + RST)
        print("iSH may not have traceroute; if unavailable you can run it on a full Linux machine.")
        time.sleep(1)
    target = input("Enter hostname or IP to traceroute: ").strip()
    if not target:
        print(R + "No target." + RST); return
        
    progress_bar("Running Trace Map", duration=3)

    # try common traceroute tools
    cmd = None
    for tool in ("traceroute","tracepath","mtr","tcptraceroute"):
        path = shutil.which(tool) if 'shutil' in globals() else None
        if path:
            cmd = [tool, "-n", target] if tool=="traceroute" else [tool, target]
            break
    if not cmd:
        # no traceroute installed - try calling system if available
        try:
            out = subprocess.check_output(["traceroute","-n",target], stderr=subprocess.STDOUT, timeout=15).decode()
            cmd_out = out
        except Exception as e:
            print(R + "Traceroute not available in this environment." + RST)
            print(Y + "Suggestion: install 'traceroute' (apk add traceroute) or run on full Linux." + RST)
            log("TRACEMAP failed (no traceroute) " + str(target))
            return
    else:
        try:
            cmd_out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30).decode()
        except Exception as e:
            cmd_out = "Error running traceroute: " + str(e)
    # save results
    safe_name = target.replace(":", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "trace_map.txt"), "w") as f:
        f.write(cmd_out)
    print(G + "Traceroute output saved to: " + rdir + RST)
    print(cmd_out)
    log("TRACEMAP " + str(target))

# ---------------- WHOIS Lookup ----------------
import subprocess

def whois_lookup_flow(learning):
    """WHOIS domain/IP lookup with save + progress bar."""
    if learning:
        print(Y + "Learning: WHOIS lookup reveals public ownership, registrar, and domain info." + RST)
        print("This command uses the system 'whois' utility if installed.")
        time.sleep(1)

    target = input("Enter domain or IP for WHOIS lookup: ").strip()
    if not target:
        print(R + "No target provided." + RST)
        return

    progress_bar("whatchin WHOIS on kaptainovi network", duration=8)

    try:
        # Run system whois
        output = subprocess.check_output(["whois", target], stderr=subprocess.STDOUT, timeout=10).decode(errors="ignore")
    except FileNotFoundError:
        print(R + "The 'whois' command is not installed." + RST)
        print(Y + "Install with: apk add whois" + RST)
        log("WHOIS failed (no whois command)")
        return
    except subprocess.TimeoutExpired:
        print(R + "WHOIS query timed out." + RST)
        log("WHOIS timeout " + target)
        return
    except Exception as e:
        print(R + f"WHOIS lookup failed: {e}" + RST)
        log("WHOIS error " + str(e))
        return

    # Show result to user
    print(G + "\nWHOIS DATA:\n" + RST)
    print(output)

    # Save to Reports
    safe_name = target.replace(":", "_").replace("/", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "whois.txt"), "w") as f:
        f.write(output)
    with open(os.path.join(rdir, "whois.json"), "w") as f:
        json.dump({"target": target, "whois_data": output, "timestamp": datetime.utcnow().isoformat()}, f, indent=2)

    print(G + "\nSaved WHOIS report to: " + rdir + RST)
    log("WHOIS lookup " + target)

# ---------------- HTTP Header Inspector ----------------
import http.client
import urllib.parse

def http_header_inspector_flow(learning):
    if learning:
        print(Y + "Learning: This inspects HTTP headers and follows redirects." + RST)
        time.sleep(1)

    url = input("Enter URL or IP: ").strip()
    if not url:
        print(R + "No URL provided." + RST)
        return

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc or parsed.path
    path = parsed.path or "/"

    progress_bar("Fetching headers", duration=5)

    max_redirects = 5
    redirect_chain = []
    current_host, current_path = host, path

    for _ in range(max_redirects):
        conn = http.client.HTTPConnection(current_host, timeout=5)
        try:
            conn.request("GET", current_path)
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            redirect_chain.append({
                "host": current_host,
                "path": current_path,
                "status": resp.status,
                "reason": resp.reason,
                "headers": headers
            })
            if resp.status in (301,302,303,307,308) and "Location" in headers:
                loc = headers["Location"]
                parsed = urllib.parse.urlparse(loc)
                current_host = parsed.netloc or current_host
                current_path = parsed.path or "/"
            else:
                break
        except Exception as e:
            print(R + f"Error fetching headers: {e}" + RST)
            break
        finally:
            conn.close()

    # Save report
    safe_name = host.replace(":", "_").replace("/", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    report_path = os.path.join(rdir, "http_header_report.json")
    with open(report_path, "w") as f:
        json.dump(redirect_chain, f, indent=2)

    print(G + f"\nSaved HTTP header report to: {rdir}" + RST)
    log("HTTPHEADER " + url)

    # Display headers
    for hop in redirect_chain:
        print(f"\n[{hop['status']}] {hop['host']}{hop['path']}")
        for k, v in hop['headers'].items():
            print(f"{k}: {v}")

# ---------------- TLS/SSL Certificate Checker ----------------
def tls_cert_flow(learning):
    if learning:
        print("Learning: TLS Checker reads cert subject/issuer and expiry.")
        time.sleep(1)
    target = input("Enter host (domain or IP) to check TLS cert: ").strip()
    if not target:
        print(R + "No target." + RST); return
    progress_bar("Fetching certificate", duration=4)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
        # basic fields
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        notBefore = cert.get("notBefore")
        notAfter = cert.get("notAfter")
        san = cert.get("subjectAltName", ())
        print(G + f"Subject: {subject}" + RST)
        print(G + f"Issuer: {issuer}" + RST)
        print("Valid from:", notBefore)
        print("Valid to:  ", notAfter)
        print("SANs:", san)
        # save
        safe_name = target.replace(":", "_")
        rdir = os.path.join(REPORTS_DIR, safe_name)
        os.makedirs(rdir, exist_ok=True)
        with open(os.path.join(rdir, "tls_cert.json"), "w") as f:
            json.dump({"target": target, "cert": cert, "timestamp": datetime.utcnow().isoformat()}, f, indent=2)
        print(G + f"\nSaved TLS cert to: {rdir}" + RST)
        log("TLSCHECK " + target)
    except Exception as e:
        print(R + "TLS check failed: " + str(e) + RST)
        log("TLSFAIL " + str(e))

# ---------------- DNS Toolkit (lookups + AXFR attempt) ----------------
def dns_toolkit_flow(learning):
    if learning:
        print("Learning: DNS Toolkit does A/CNAME/MX/NS lookups and attempts AXFR if possible.")
        time.sleep(1)
    domain = input("Enter domain to query (example.com): ").strip()
    if not domain:
        print(R + "No domain." + RST); return
    progress_bar("Querying DNS", duration=4)
    results = {}
    # simple A and CNAME using getaddrinfo
    try:
        infos = socket.getaddrinfo(domain, None)
        adds = sorted(set(i[4][0] for i in infos if i and i[4]))
        results["addresses"] = adds
    except Exception:
        results["addresses"] = []
    # try system nslookup/dig for more (best-effort)
    try:
        out_ns = subprocess.check_output(["nslookup", domain], stderr=subprocess.STDOUT, timeout=6).decode(errors="ignore")
        results["nslookup"] = out_ns
    except Exception:
        results["nslookup"] = "nslookup not available"
    # try AXFR against NS records discovered (best-effort)
    results["axfr"] = {}
    # parse NS from nslookup output (very simple heuristic)
    try:
        ns_lines = out_ns.splitlines()
        nslist = []
        for ln in ns_lines:
            if "name =" in ln or "nameserver" in ln.lower():
                parts = ln.split()
                nslist.append(parts[-1].strip("."))
        nslist = list(dict.fromkeys(nslist))[:4]
        for ns in nslist:
            try:
                axfr_out = subprocess.check_output(["dig", "axfr", domain, "@" + ns], stderr=subprocess.STDOUT, timeout=8).decode(errors="ignore")
                results["axfr"][ns] = axfr_out
            except Exception:
                results["axfr"][ns] = "axfr attempt failed or dig not available"
    except Exception:
        pass
    # save + print
    safe_name = domain.replace(":", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "dns_toolkit.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(rdir, "dns_toolkit.txt"), "w") as f:
        f.write(str(results))
    print(G + f"\nSaved DNS toolkit report to: {rdir}" + RST)
    log("DNSTOOL " + domain)

# ---------------- Subdomain Enumerator (wordlist-lite) ----------------
def subdomain_enum_flow(learning):
    if learning:
        print("Learning: Subdomain Enumerator tries a small built-in list to find hosts.")
        time.sleep(1)
    domain = input("Enter domain (example.com): ").strip()
    if not domain:
        print(R + "No domain." + RST); return
    wordlist = ["www","mail","api","dev","test","staging","admin","ftp","beta"]
    found = []
    progress_bar("Enumerating subdomains", duration=4)
    for w in wordlist:
        host = f"{w}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append((host, ip))
            print(G + f"Found: {host} -> {ip}" + RST)
        except:
            pass
    safe_name = domain.replace(":", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "subdomains.json"), "w") as f:
        json.dump({"found": found, "timestamp": datetime.utcnow().isoformat()}, f, indent=2)
    print(G + f"\nSaved subdomain results to: {rdir}" + RST)
    log("SUBENUM " + domain)

# ---------------- HTTP Directory Probe (lite) ----------------
def http_dir_probe_flow(learning):
    if learning:
        print("Learning: Directory probe uses a small path list to test common admin or backup paths.")
        time.sleep(1)
    target = input("Enter URL or host (example.com or https://example.com): ").strip()
    if not target:
        print(R + "No target." + RST); return
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.hostname
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    paths = ["/admin","/backup.zip","/backup.tar.gz","/robots.txt","/config.php","/.env"]
    progress_bar("Probing common paths", duration=4)
    results = []
    for p in paths:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((host, port))
            if scheme == "https":
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=host)
            req = f"HEAD {p} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            data = s.recv(1024).decode(errors="ignore")
            s.close()
            if "200" in data.splitlines()[0] or "301" in data.splitlines()[0] or "403" in data.splitlines()[0]:
                results.append((p, data.splitlines()[0]))
                print(G + f"{p}: {data.splitlines()[0]}" + RST)
        except:
            pass
    safe_name = host.replace(":", "_")
    rdir = os.path.join(REPORTS_DIR, safe_name)
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "dir_probe.json"), "w") as f:
        json.dump({"results": results, "timestamp": datetime.utcnow().isoformat()}, f, indent=2)
    print(G + f"\nSaved dir probe to: {rdir}" + RST)
    log("DIRPROBE " + target)

# ---------------- SMTP Open Relay Test (careful) ----------------
def smtp_relay_test_flow(learning):
    if learning:
        print("Learning: SMTP test performs a very simple handshake to detect open relay behavior. Run only on systems you own.")
        time.sleep(1)
    target = input("Enter SMTP host (hostname or IP): ").strip()
    if not target:
        print(R + "No target." + RST); return
    port = input("SMTP port [25]: ").strip() or "25"
    try:
        port = int(port)
    except:
        port = 25
    progress_bar("Testing SMTP", duration=4)
    try:
        s = smtplib.SMTP(target, port, timeout=8)
        s.ehlo_or_helo_if_needed()
        code = s.noop()[0]
        # we will not attempt mail-from/rcpt-to tests by default; only check basic response
        print(G + f"SMTP server responded: {code}" + RST)
        s.quit()
        safe_name = target.replace(":", "_")
        rdir = os.path.join(REPORTS_DIR, safe_name)
        os.makedirs(rdir, exist_ok=True)
        with open(os.path.join(rdir, "smtp_test.txt"), "w") as f:
            f.write(f"SMTP basic response: {code}\n")
        log("SMTPTEST " + target)
    except Exception as e:
        print(R + "SMTP test failed: " + str(e) + RST)
        log("SMTPERR " + str(e))

# ---------------- Service Fingerprint DB (save example banners) ----------------
FINGERPRINT_FILE = os.path.join(HOME, ".kaptainovi_fingerprints.json")
def load_fingerprints():
    try:
        with open(FINGERPRINT_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_fingerprints(fp):
    try:
        with open(FINGERPRINT_FILE, "w") as f:
            json.dump(fp, f, indent=2)
    except:
        pass

def service_fingerprint_flow(learning):
    if learning:
        print("Learning: Service fingerprint saves short banner snippets to a local DB to help future matches.")
        time.sleep(1)
    target = input("Host/IP to fingerprint (use after Smart Recon or manual): ").strip()
    if not target:
        print(R + "No target." + RST); return
    port = input("Port to capture banner [22]: ").strip() or "22"
    try:
        port = int(port)
    except:
        port = 22
    progress_bar("Capturing banner", duration=3)
    try:
        s = socket.socket()
        s.settimeout(4)
        s.connect((target, port))
        try:
            data = s.recv(512)
        except:
            data = b""
        s.close()
        banner = data.decode(errors="ignore").splitlines()
        print(G + "Banner (first lines):" + RST)
        for ln in banner[:5]:
            print("  " + ln)
        # store into fingerprint DB
        fp = load_fingerprints()
        key = f"{target}:{port}"
        fp[key] = {"banner": banner[:5], "added": datetime.utcnow().isoformat()}
        save_fingerprints(fp)
        print(G + "Saved fingerprint to local DB." + RST)
        log("FINGERPRINT " + key)
    except Exception as e:
        print(R + "Capture failed: " + str(e) + RST)
        log("FINGERERR " + str(e))

# ---------------- Host Summary + Tips ----------------
def host_summary_flow(learning):
    """
    Build a combined Host Summary from saved reports and produce actionable tips.
    Saves summary.txt and summary.json into the report folder.
    """
    if learning:
        print(Y + "Learning: Host Summary now includes actionable tips based on discovered data." + RST)
        time.sleep(1)

    target = input("Enter target folder name or hostname (as shown in Reports): ").strip()
    if not target:
        print(R + "No target provided." + RST)
        return

    rdir = os.path.join(REPORTS_DIR, target)
    if not os.path.isdir(rdir):
        print(R + "Report folder not found: " + rdir + RST)
        return

    progress_bar("Building host summary", duration=3)

    summary = {"target": target, "generated": datetime.utcnow().isoformat(), "notes": [], "tips": []}

    def _load_json(fn):
        path = os.path.join(rdir, fn)
        if os.path.isfile(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    return json.load(f)
            except:
                return None
        return None

    # --- Load known reports (best-effort) ---
    tls = _load_json("tls_cert.json") or _load_json("tls_cert_report.json")
    http_headers = _load_json("http_header_report.json") or _load_json("http_headers.json") or _load_json("http_headers_report.json")
    whois = _load_json("whois.json")
    dns = _load_json("dns_toolkit.json")
    nmap = _load_json("nmap_lite.json") or _load_json("nmap.json")
    subs = _load_json("subdomains.json")
    dirp = _load_json("dir_probe.json")
    pt = _load_json("port_timing.json")
    smart = _load_json("smart_recon.json")
    smtp_txt = None
    smtp_path = os.path.join(rdir, "smtp_test.txt")
    if os.path.isfile(smtp_path):
        try:
            with open(smtp_path, "r", errors="ignore") as f:
                smtp_txt = f.read().strip()
        except:
            smtp_txt = None

    # --- Basic parsed summary fields (same approach as before) ---
    # TLS parsing
    summary["tls"] = None
    if tls:
        cert = tls.get("cert") if isinstance(tls, dict) and tls.get("cert") else tls
        subject = issuer = not_before = not_after = None
        sans = []
        if isinstance(cert, dict):
            subject = cert.get("subject")
            issuer = cert.get("issuer")
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            sans = [s[1] for s in cert.get("subjectAltName", [])] if cert.get("subjectAltName") else cert.get("san") or []
        summary["tls"] = {"subject": subject, "issuer": issuer, "valid_from": not_before, "valid_to": not_after, "sans": sans}

    # HTTP parsing
    http_summary = {}
    if http_headers:
        chain = http_headers if isinstance(http_headers, list) else http_headers.get("redirect_chain") or http_headers.get("headers") or http_headers
        if isinstance(chain, list) and chain:
            first = chain[0]; last = chain[-1]
            http_summary["initial_status"] = first.get("status")
            http_summary["final_status"] = last.get("status")
            http_summary["final_host"] = last.get("host")
            headers = last.get("headers", {}) if isinstance(last, dict) else {}
            http_summary["server"] = headers.get("Server") or headers.get("server")
            http_summary["hsts"] = bool(headers.get("Strict-Transport-Security"))
            http_summary["location"] = headers.get("Location") or headers.get("location")
            http_summary["cache"] = headers.get("CF-Cache-Status") or headers.get("cf-cache-status")
        else:
            http_summary = {}
    summary["http"] = http_summary or None

    # WHOIS parsing
    if whois:
        registrar = whois.get("registrar") or whois.get("Registrar")
        created = whois.get("creation_date") or whois.get("created")
        expires = whois.get("expiration_date") or whois.get("expires")
        name = whois.get("domain_name") or whois.get("Domain Name")
        summary["whois"] = {"registrar": registrar, "created": created, "expires": expires, "domain": name}
    else:
        summary["whois"] = None

    # DNS parsing
    if dns:
        adds = dns.get("addresses") or dns.get("A") or dns.get("addresses_found")
        summary["dns"] = {"addresses": adds, "nslookup": dns.get("nslookup")}
    else:
        summary["dns"] = None

    # Nmap/ports parsing
    open_ports = []
    if nmap and isinstance(nmap, dict):
        for k, v in nmap.items():
            try:
                p = int(k)
            except:
                continue
            if isinstance(v, str) and ("OPEN" in v.upper() or "open" in v):
                open_ports.append((p, v if isinstance(v, str) else "open"))
            elif isinstance(v, dict) and v.get("open"):
                open_ports.append((p, v.get("banner") or "open"))
    summary["ports"] = {"open": sorted(open_ports)} if open_ports else None

    # Subdomains, dir probe, port timing, banners
    summary["subdomains"] = (subs.get("found") if isinstance(subs, dict) else subs) or None
    summary["dir_probe"] = dirp.get("results") if dirp and isinstance(dirp, dict) else None
    summary["port_timing"] = pt or None
    summary["banners"] = smart.get("banners") if smart and isinstance(smart, dict) else None
    summary["smtp"] = smtp_txt

    # --- Heuristics / Tips generation ---
    tips = []

    # TLS tips
    if summary["tls"]:
        not_after = summary["tls"].get("valid_to")
        sans = summary["tls"].get("sans") or []
        issuer = summary["tls"].get("issuer")
        # expiry check (best-effort parse)
        try:
            if not_after:
                # try ISO-like or openssl style, safe compare by prefix year if found
                if " " in not_after:
                    # openssl style e.g. "Mar 25 04:43:22 2026 GMT"
                    parts = not_after.strip().split()
                    year = int(parts[-2]) if len(parts) >= 2 and parts[-2].isdigit() else None
                else:
                    year = int(not_after[:4]) if len(not_after) >= 4 and not_after[:4].isdigit() else None
                if year and year <= datetime.utcnow().year:
                    tips.append(("TLS expired", "Certificate appears expired or expiring this year - consider renewing or verifiying live status."))
                elif year and (year - datetime.utcnow().year) <= 0:
                    tips.append(("TLS expiry", "Certificate near expiry - verify validity or set monitoring."))
        except:
            pass
        # SAN checks
        if any(".onion" in s for s in sans):
            tips.append(("Onion present", "Certificate includes a .onion name - operator likely serves Tor and clearnet. Good for privacy-aware users."))
        # issuer check
        if issuer:
            tips.append(("Issuer found", f"Certificate issued by {issuer}. Verify expected CA if you manage this host."))

    else:
        tips.append(("No TLS report", "No TLS certificate data found. Run TLS check to capture certificate details."))

    # HTTP tips
    http = summary.get("http")
    if http:
        if http.get("final_status") in (301,302,303,307,308):
            loc = http.get("location")
            tips.append(("Redirect seen", f"Site redirects ({http.get('final_status')}) to {loc}. Follow redirect for final checks."))
        if not http.get("hsts"):
            tips.append(("HSTS missing", "HSTS header not present - site may be vulnerable to protocol downgrade attacks. Consider enabling HSTS."))
        server = (http.get("server") or "").lower()
        if "cloudflare" in server:
            tips.append(("Behind CDN", "Site appears behind Cloudflare - site may be vulnerable to protocol downgrade attacks. Consider enabling HSTS."))
        server = (http.get("server") or "").lower()
        if "cloudflare" in server:
            tips.append(("Behind CDN", "Site appears behind Cloudflare -some headers and IPs will reflect CDN, not origin."))
    else:
        tips.append(("No HTTP header report", "Run HTTP Header Inspector to capture server and security headers."))

    # WHOIS tips
    who = summary.get("whois")
    if who:
        if who.get("expires"):
            # best-effort check for expiry year
            try:
                if isinstance(who.get("expires"), str) and who.get("expires")[:4].isdigit():
                    exyear = int(who.get("expires")[:4])
                    if exyear <= datetime.utcnow().year:
                        tips.append(("Domain expiry", "Domain registration expires soon or has expired - consider renewal/monitoring."))
            except:
                pass
        if not who.get("registrar"):
            tips.append(("Whois limited", "WHOIS data incomplete - registrar privacy or missing data."))
    else:
        tips.append(("No WHOIS", "No WHOIS data found - run WHOISIT tool for domain ownership and dates."))

    # DNS tips
    dnsinfo = summary.get("dns")
    if dnsinfo and dnsinfo.get("addresses"):
        if len(dnsinfo["addresses"]) > 3:
            tips.append(("Multiple IPs", "Domain resolves to multiple IPs - likely CDN or load-balanced setup."))
    else:
        tips.append(("No DNS addresses", "No DNS A/AAAA records found in saved DNS report."))

    # Ports & banners tips
    ports = summary.get("ports")
    if ports and ports.get("open"):
        common_risky = [21,22,23,3306,3389,5900]
        for p,info in ports["open"]:
            if p in common_risky:
                tips.append(("Open risky port", f"Port {p} open - review service exposure (may indicate management ports open to internet)."))
        tips.append(("Open ports summary", f"{len(ports['open'])} open port(s) recorded. Review services and restrict via firewall if unnecessary."))
    else:
        tips.append(("No open ports recorded", "No open ports found in saved scans; run NMAP LITE if you expect to find services."))

    # Subdomain tips
    if summary.get("subdomains"):
        tips.append(("Subdomains discovered", f"Found {len(summary['subdomains'])} subdomain(s). Consider scanning them individually for issues."))

    # Dir probe tips
    if summary.get("dir_probe"):
        tips.append(("Directory findings", "Directory probe found potential interesting files/paths - review manually for exposed data."))

    # SMTP tips
    if summary.get("smtp"):
        tips.append(("SMTP result", "SMTP server checked - review response for open-relay behaviour. Do not send unsolicited tests."))

    # Port timing
    if summary.get("port_timing"):
        slow = [p for p,v in (summary["port_timing"].items() if isinstance(summary["port_timing"], dict) else []) if v and v > 1000]
        if slow:
            tips.append(("Slow ports", "Some ports show high latency - may indicate filtering or overloaded service."))

    # Banner heuristics
    if summary.get("banners"):
        # look for common server strings
        btxt = json.dumps(summary["banners"])
        if "nginx" in btxt.lower():
            tips.append(("Nginx detected", "Service banner suggests nginx; review nginx configs for server tokens and headers."))
        if "apache" in btxt.lower():
            tips.append(("Apache detected", "Service banner suggests Apache; review .htaccess and server tokens."))

    # Generic final tip
    tips.append(("Keep monitoring", "Consider scheduling regular scans and enable alerts for certificate expiry and integrity vault changes."))

    # Attach tips to summary
    summary["tips"] = [{"title": t[0], "suggestion": t[1]} for t in tips]

    # --- Build human-readable summary lines ---
    lines = []
    lines.append("Host Summary for: " + target)
    lines.append("Generated: " + summary["generated"])
    lines.append("-" * 50)

    if summary.get("dns") and summary["dns"].get("addresses"):
        lines.append("IP(s): " + ", ".join(summary["dns"]["addresses"]))
    if summary.get("whois") and summary["whois"].get("registrar"):
        lines.append("Registrar: " + str(summary["whois"].get("registrar")))
    lines.append("")

    lines.append("TLS Certificate:")
    if summary["tls"]:
        lines.append("  Issuer: " + str(summary["tls"].get("issuer")))
        lines.append("  Valid from: " + str(summary["tls"].get("valid_from")))
        lines.append("  Valid to:   " + str(summary["tls"].get("valid_to")))
        if summary["tls"].get("sans"):
            lines.append("  SANs: " + ", ".join(summary["tls"]["sans"]))
        lines.append("")
    else:
        lines.append("  No TLS report saved.")
        lines.append("")

    lines.append("HTTP / Headers:")
    if summary["http"]:
        lines.append("  Initial status: " + str(summary["http"].get("initial_status")))
        lines.append("  Final status:   " + str(summary["http"].get("final_status")))
        lines.append("  Server:         " + str(summary["http"].get("server")))
        lines.append("  HSTS:           " + ("YES" if summary["http"].get("hsts") else "NO"))
        if summary["http"].get("location"):
            lines.append("  Redirects to:   " + str(summary["http"].get("location")))
        lines.append("")
    else:
        lines.append("  No HTTP header report.")
        lines.append("")

    lines.append("Open Ports (from scans):")
    if summary["ports"] and summary["ports"]["open"]:
        for p,v in summary["ports"]["open"]:
            lines.append(f"  - {p}: {v}")
    else:
        lines.append("  No open ports recorded.")
    lines.append("")

    lines.append("Subdomains found:")
    if summary["subdomains"]:
        for s in summary["subdomains"]:
            if isinstance(s, (list,tuple)) and len(s)>=2:
                lines.append(f"  - {s[0]} -> {s[1]}")
            else:
                lines.append(f"  - {s}")
    else:
        lines.append("  None recorded.")
    lines.append("")

    if summary["dir_probe"]:
        lines.append("Interesting directory probe results:")
        for p in summary["dir_probe"]:
            lines.append(f"  {p[0]} - {p[1]}")
        lines.append("")

    if summary["banners"]:
        lines.append("Banners captured (sample):")
        cnt = 0
        for port, lineset in (summary["banners"].items() if isinstance(summary["banners"], dict) else []):
            if cnt >= 5: break
            lines.append(f"  [{port}] {str(summary['banners'][port])[:120]}")
            cnt += 1
        lines.append("")

    if summary["smtp"]:
        lines.append("SMTP test result:")
        lines.append("  " + str(summary["smtp"]))
        lines.append("")

    # --- Tips section printed at end ---
    lines.append("Actionable Tips:")
    for t in summary["tips"]:
        lines.append(f" - {t['title']}: {t['suggestion']}")
    lines.append("")

    # save summary files
    summary_txt = "\n".join(lines)
    try:
        with open(os.path.join(rdir, "summary.txt"), "w") as f:
            f.write(summary_txt)
        with open(os.path.join(rdir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
        print(G + f"Saved summary to: {rdir}/summary.txt and summary.json" + RST)
        log("HOST_SUMMARY " + target)
    except Exception as e:
        print(R + "Failed saving summary: " + str(e) + RST)

    print("\n" + summary_txt)
    input("\nPress Enter to continue...")

# ---------------- Integrity Vault (file watchlist) ----------------

import hashlib
import json
import os
from datetime import datetime

# --- Integrity Vault Paths ---
VAULT_FILE = os.path.join(HOME, ".kaptainovi_vault.json")
LOG_FILE = os.path.join(HOME, ".kaptainovi_vault_log.json")

# --- Utility Functions ---
def file_sha256(path):
    """Generate SHA256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(4096)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except:
        return None


def load_vault():
    try:
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_vault(vault):
    try:
        with open(VAULT_FILE, "w") as f:
            json.dump(vault, f, indent=2)
    except:
        pass


# --- Integrity Vault Flow ---
def integrity_vault_flow(learning):
    vault = load_vault()

    if learning:
        print(Y + "Learning: The Integrity Vault now tracks every file change with timestamps and logs history." + RST)
        time.sleep(1)

    while True:
        print("")
        print(C + "=== Integrity Vault ===" + RST)
        print("1) List watched files")
        print("2) Add file to watchlist")
        print("3) Remove file from watchlist")
        print("4) Check now (compare hashes)")
        print("5) View change history")
        print("x) Back")
        choice = input("Choice: ").strip().lower()

        # 1) List watched files
        if choice == "1":
            if not vault:
                print(R + "No watched files." + RST)
            else:
                print(C + "\n--- Watched Files ---" + RST)
                for path, meta in vault.items():
                    last = meta.get("last_changed", meta.get("added", "Unknown"))
                    print(f"- {path}")
                    print(f"  Hash: {meta.get('hash')[:12]}...")
                    print(f"  Last Updated: {last}\n")
            input("\nPress Enter...")

        # 2) Add file
        elif choice == "2":
            path = input("Path to file to watch: ").strip()
            if not os.path.isfile(path):
                print(R + "File not found." + RST)
                continue
            h = file_sha256(path)
            if not h:
                print(R + "Could not hash file." + RST)
                continue
            vault[path] = {"hash": h, "added": datetime.utcnow().isoformat()}
            save_vault(vault)
            print(G + "File added and saved." + RST)
            log("VAULT add " + path)

        # 3) Remove file
        elif choice == "3":
            path = input("Path to remove: ").strip()
            if path in vault:
                vault.pop(path, None)
                save_vault(vault)
                print(G + "Removed." + RST)
                log("VAULT remove " + path)
            else:
                print(R + "Not in watchlist." + RST)

        # 4) Check now (compare hashes)
        elif choice == "4":
            if not vault:
                print(R + "No files to check." + RST)
                continue

            # Load history
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r") as lf:
                        log_history = json.load(lf)
                except:
                    log_history = []
            else:
                log_history = []

            updated = False
            for path, meta in list(vault.items()):
                cur = file_sha256(path)
                old = meta.get("hash")
                last_update = meta.get("last_changed", meta.get("added", "Unknown"))

                if cur is None:
                    print(R + f"[MISSING] {path}" + RST)
                    continue

                if cur != old:
                    print(Y + f"[CHANGED] {path}" + RST)
                    print(f"Old hash: {old}")
                    print(f"New hash: {cur}")
                    print(f"Last updated: {last_update}")

                    now = datetime.utcnow().isoformat()
                    vault[path]["hash"] = cur
                    vault[path]["last_changed"] = now
                    updated = True

                    log_entry = {
                        "file": path,
                        "old_hash": old,
                        "new_hash": cur,
                        "previous_timestamp": last_update,
                        "new_timestamp": now
                    }
                    log_history.append(log_entry)
                    log("VAULT changed " + path)
                else:
                    print(G + f"[OK] {path}" + RST)
                    print(f"Hash: {cur}")
                    print(f"Last updated: {last_update}")

            save_vault(vault)
            if updated:
                with open(LOG_FILE, "w") as lf:
                    json.dump(log_history, lf, indent=2)
                print(G + "\nVault updated with new timestamps." + RST)
            else:
                print(G + "\nAll files unchanged." + RST)
            input("\nPress Enter...")

        # 5) View change history
        elif choice == "5":
            if not os.path.exists(LOG_FILE):
                print(R + "No log history found." + RST)
            else:
                with open(LOG_FILE, "r") as lf:
                    try:
                        history = json.load(lf)
                    except:
                        history = []
                    if not history:
                        print(R + "No recorded changes." + RST)
                    else:
                        print(C + "\n--- Integrity Change History ---" + RST)
                        for entry in history[-10:]:  # Show last 10
                            print(f"\nFile: {entry['file']}")
                            print(f"Changed at: {entry['new_timestamp']}")
                            print(f"Old hash: {entry['old_hash']}")
                            print(f"New hash: {entry['new_hash']}")
                            print(f"Previous timestamp: {entry['previous_timestamp']}")
            input("\nPress Enter...")

        # Exit
        elif choice == "x":
            break
        else:
            continue

# ---------------- Clean Reports Flow ----------------
def clean_reports_flow(learning):
    print("1) List reports")
    print("2) Delete one report")
    print("3) Delete ALL reports")
    print("x) Back")
    choice = input("Choice: ").strip().lower()

    if choice == "1":
        print("\nSaved Reports:\n")
        for root, dirs, files in os.walk(REPORTS_DIR):
            if root == REPORTS_DIR:
                for d in dirs:
                    print(" -", d)
        pause()

    elif choice == "2":
        target = input("Enter report folder to delete: ").strip()
        rdir = os.path.join(REPORTS_DIR, target)
        if os.path.isdir(rdir):
            confirm = input(f"Are you sure you want to delete {target}? (y/n): ").strip().lower()
            if confirm == "y":
                progress_bar("Deleting report", duration=2)
                os.system(f"rm -rf '{rdir}'")
                print(G + f"\nDeleted {target}" + RST)
                log("CLEAN one " + target)
            else:
                print(Y + "Cancelled." + RST)
        else:
            print(R + "Report not found." + RST)
        pause()

    elif choice == "3":
        confirm = input("Are you sure you want to delete ALL reports? (y/n): ").strip().lower()
        if confirm == "y":
            progress_bar("Clearing all reports", duration=3)
            os.system(f"rm -rf '{REPORTS_DIR}'/*")
            print(G + "\nAll reports deleted." + RST)
            log("CLEAN all")
        else:
            print(Y + "Cancelled." + RST)
        pause()

    else:
        return

# ---------------- Port Timing & Recon (high-octane) ----------------
def port_timing_flow(learning):
    """
    High-octane port timing & lightweight reconnaissance:
    - resolves target, times connect for ports, attempts tiny banner grabs
    - saves JSON + TXT report under REPORTS_DIR/<target>/port_timing_<timestamp>/
    - prints actionable tips based on heuristics
    """
    if learning:
        print(Y + "Learning: Port Timing will measure latency, attempt small banner grabs, and suggest follow-up actions." + RST)
        time.sleep(1)

    target = input("Enter host or IP to test: ").strip()
    if not target:
        print(R + "No target provided." + RST)
        return

    # Resolve ip
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        print(R + f"DNS resolution failed for {target}: {e}" + RST)
        return

    # Default ports (common + interesting)
    DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,445,465,587,631,993,995,1433,1521,2049,3306,3389,4444,5000,5432,5900,6379,6667,8080,8443,9000]
    ports_input = input("Ports to test (comma or range) [default common set]: ").strip()
    if not ports_input:
        ports = DEFAULT_PORTS
    else:
        # parse port input
        parts = ports_input.split(",")
        ports = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if "-" in p:
                try:
                    a,b = p.split("-",1)
                    for i in range(int(a), int(b)+1):
                        ports.append(int(i))
                except:
                    pass
            else:
                try:
                    ports.append(int(p))
                except:
                    pass
        if not ports:
            ports = DEFAULT_PORTS

    # small service hints
    PORT_HINTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
        6379: "Redis", 5432: "Postgres", 1521: "Oracle", 27017: "MongoDB"
    }
    RISKY_PORTS = {21,23,3306,3389,5900,6379,5432,1521,445}

    # report setup
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_target = target.replace(":", "_").replace("/", "_")
    rdir = os.path.join(REPORTS_DIR, safe_target, f"port_timing_{ts}")
    os.makedirs(rdir, exist_ok=True)

    progress_bar(f"Timing {len(ports)} ports on {target} ({ip})", duration=3)

    results = {
        "target": target,
        "resolved_ip": ip,
        "timestamp": datetime.utcnow().isoformat(),
        "ports_tested": ports,
        "results": {},
        "summary": {}
    }

    # helper: tiny banner grab (non-blocking small read)
    def grab_banner(ipaddr, port, timeout=2.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ipaddr, port))
            # try small recv
            try:
                data = s.recv(512)
            except:
                data = b""
            s.close()
            if not data:
                return ""
            return data.decode(errors="ignore").strip().splitlines()[:4]
        except:
            return ""

    open_ports = []
    timing_data = {}
    for p in ports:
        start = time.time()
        status = "closed"
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, p))
            status = "open"
            # measure elapsed precisely after connect
            elapsed = (time.time() - start) * 1000.0
            # try small banner
            banner_lines = []
            try:
                # some services send banners immediately (SSH, SMTP)
                s.settimeout(0.8)
                data = s.recv(512)
                if data:
                    banner_lines = data.decode(errors="ignore").strip().splitlines()[:4]
            except:
                banner_lines = []
            try:
                s.close()
            except:
                pass
            banner = banner_lines
            timing = round(elapsed, 1)
            timing_data[p] = timing
            if status == "open":
                open_ports.append(p)
            results["results"][str(p)] = {"status": status, "rtt_ms": timing, "hint": PORT_HINTS.get(p), "banner": banner}
        except Exception as e:
            # closed or filtered, measure elapsed until failure
            elapsed = (time.time() - start) * 1000.0
            timing_data[p] = None
            results["results"][str(p)] = {"status": "closed/filtered", "rtt_ms": None, "hint": PORT_HINTS.get(p), "banner": []}
        # small sleep to avoid hammering
        time.sleep(0.02)

    # summary heuristics
    results["summary"]["open_count"] = len(open_ports)
    results["summary"]["open_ports"] = sorted(open_ports)
    if open_ports:
        # categorize
        slow_ports = []
        for p in open_ports:
            rtt = results["results"][str(p)].get("rtt_ms")
            if rtt is not None and rtt > 1000:
                slow_ports.append((p, rtt))
        results["summary"]["slow_ports"] = slow_ports

    # Build actionable tips
    tips = []
    if results["summary"]["open_count"] == 0:
        tips.append({"title":"No open ports detected","suggestion":"No open ports recorded for the ports you tested. If you expected services, try a wider port list or run from a different network."})
    else:
        for p in results["summary"]["open_ports"]:
            hint = results["results"][str(p)].get("hint") or "service"
            rtt = results["results"][str(p)].get("rtt_ms")
            banner = results["results"][str(p)].get("banner") or []
            # risky port warnings
            if p in RISKY_PORTS:
                tips.append({"title":f"Risky service exposed: {p}", "suggestion":f"Port {p} ({hint}) is open. Confirm if this should be internet-exposed; if not, firewall it."})
            # slow port warnings
            if rtt is None:
                tips.append({"title":f"{p} possibly filtered", "suggestion":f"Port {p} did not respond in time (filtered or closed). Consider testing from another vantage."})
            elif rtt > 1000:
                tips.append({"title":f"{p} slow response ({rtt} ms)", "suggestion":f"Port {p} shows high latency. This can indicate filtering, load, or network issues."})
            elif rtt > 250:
                tips.append({"title":f"{p} moderate latency ({rtt} ms)", "suggestion":f"Port {p} has higher-than-normal latency; investigate service load."})
            elif rtt <= 100:
                tips.append({"title":f"{p} responsive ({rtt} ms)", "suggestion":f"Port {p} is responsive; service is reachable from this network."})
            # banner heuristics
            if banner:
                btxt = " ".join(banner).lower()
                if "ssh" in btxt:
                    tips.append({"title":f"SSH banner on {p}", "suggestion":"SSH detected -  ensure key auth and disable password login if not required."})
                if "http" in btxt or any(h in btxt for h in ("apache","nginx","varnish","cloudflare")):
                    tips.append({"title":f"Web service on {p}", "suggestion":"Webserver detected - check headers, TLS cert, and security headers."})
                # include short sample banner line in suggestion for context
                tips.append({"title":f"Banner sample @ {p}", "suggestion":(banner[0] if banner else "n/a")})

    # top-level tips
    if any("cloudflare" in ((" ".join((b or [])).lower())) for b in (results["results"][str(p)].get("banner") for p in results["results"] if results["results"][str(p)].get("banner"))):
        tips.append({"title":"CDN detected","suggestion":"Some responses indicate CDN (Cloudflare). Origin IP may differ from observed IP."})

    # Save output
    results["tips"] = tips
    try:
        json_path = os.path.join(rdir, "port_timing.json")
        txt_path = os.path.join(rdir, "port_timing.txt")
        with open(json_path, "w") as jf:
            json.dump(results, jf, indent=2)
        with open(txt_path, "w") as tf:
            tf.write(f"Port Timing Report for {target} ({ip})\nGenerated: {results['timestamp']}\n\n")
            tf.write(f"Open ports: {results['summary'].get('open_ports')}\n\n")
            for p in sorted(results["results"].keys(), key=lambda x:int(x)):
                info = results["results"][p]
                tf.write(f"Port {p}: {info['status']}\n")
                tf.write(f"  RTT ms: {info.get('rtt_ms')}\n")
                if info.get("hint"):
                    tf.write(f"  Hint: {info.get('hint')}\n")
                if info.get("banner"):
                    tf.write(f"  Banner: {info.get('banner')[:2]}\n")
                tf.write("\n")
            tf.write("\nActionable tips:\n")
            for t in tips:
                tf.write(f" - {t['title']}: {t['suggestion']}\n")
        print(G + f"\nSaved port timing report to: {rdir}" + RST)
        log("PORTTIMING " + target)
    except Exception as e:
        print(R + "Failed to save report: " + str(e) + RST)

    # Print summary to screen (concise)
    print("\n== Port Timing Summary ==")
    print("Target:", target, "Resolved IP:", ip)
    print("Open ports:", results["summary"].get("open_ports") or "None")
    if results["summary"].get("slow_ports"):
        for p,rtt in results["summary"]["slow_ports"]:
            print(Y + f"  Slow: {p} - {rtt} ms" + RST)
    print("\nActionable tips (top 6):")
    for t in results["tips"][:6]:
        print(" -", t["title"], ":", t["suggestion"])

    input("\nPress Enter to continue...")


# ---------------- main menu loading screen ----------------

import time
import os

def welcome_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

    # Tie-dye banner
    banner = tie_dye(" KAPTAINOVI SECURITY SUITE ")
    print("\n" + banner)
    print("-" * 60)

    # Animated loading bar
    print("\033[38;5;220mInitializing system modules...\033[0m")  # Gold text
    bar_length = 40
    for i in range(bar_length + 1):
        bar = "01001100011011110110000101100100011010010110111001100111" * i + "-" * (bar_length - i)
        sys.stdout.write(f"\rLoading: [{bar}] {i * 100 // bar_length}%")
        sys.stdout.flush()
        time.sleep(0.05)
    print("\n\033[38;5;39mCore utilities loaded and ready boss.\033[0m")  # Blue text
    time.sleep(0.25)
    print("\033[38;5;205mActivating AI-assisted Learning Mode........Activated.\033[0m")  # Red text
    time.sleep(1)
    print("\033[38;5;45mSyncing Integrity Vault...Integrity vault Activated.\033[0m")  # Teal text
    time.sleep(2)
    print("\033[38;5;82mNetwork modules ready.\033[0m")  # Greenish TEXT
    time.sleep(3.5)
    print("\033[38;5;220mPorts are open for business.\033[0m")  # Gold TEXT
    time.sleep(4)
    print("-" * 220)

    # Ethical warning
    print("\033[1;41m" + "  WARNING: THIS TOOL IS NOT A TOY  ".center(60) + "\033[0m")  # Red background
    print("\033[1;31mYou MUST only test systems you have explicit permission to test. or dont the choice is yours\033[0m")
    print("\033[1;31mUnauthorized testing is illegal and unethical. just remember we do it for good not evil.\033[0m")
    print("-" * 90)

    # Require ethical agreement
    agreed = ""
    while agreed.lower() != "i agree":
        agreed = input("Type 'I AGREE' to confirm you will only test with permission: ").strip()
    os.system('clear' if os.name != 'nt' else 'cls')

    # Tie-dye banner again after agreement
    print("\n" + banner)
    print("-" * 60)

    # Credits section
    print("\033[38;5;205mCredits:\033[0m")  # Pink
    print(f"\033[38;5;39mKaptainovi Assistant\033[0m - Augees for brainstorming and building")
    print(f"\033[31mWhiteHat\033[97mKali\033[34mBoy\033[0m") 
    print(f"If you wanna donate please doso with xrp\033[38;5;39m rh2uR8aZULP6gLJFj9B9uqYxC1uiRA4z4V \033[0m all donations go to making app better more support and updates")
    print("-" * 120)

    print("\033[38;5;118mTime to recon stay visiual - Press [ENTER] to continue but only if you are ready.\033[0m")
    input()
    os.system('clear' if os.name != 'nt' else 'cls')

#--------------------------------------------

# ------------------ NETWORK SCANNER (iSH Edition) -------------
# Mode 3: User may enter:
#   - A full subnet (ex: 192.168.1.0/24)
#   - A single IP, system auto-deduces subnet (ex: 192.168.1.44 b
# Fully threaded ping sweep, full REPORTS_DIR reporting.

import threading
import subprocess
import socket
import ipaddress
import time
import os

def ask_for_subnet():
    print("Enter subnet OR a single IP to find the victim (examples):")
    print(" - 192.168.1.0/24")
    print(" - 10.0.0.55")
    print(" - 172.16.22.14")
    print("Or PRESS ENTER for autovictim")

    raw = input("Input: ").strip()

    # AUTO-DETECT MODE
    if raw == "":
        auto_ip = None

        # Method 1: hostname -I
        try:
            out = subprocess.check_output(["hostname", "-I"], stderr=subprocess.STDOUT).decode().strip()
            if out:
                auto_ip = out.split()[0]
        except:
            pass

        # Method 2: Python socket fallback
        if not auto_ip:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                auto_ip = s.getsockname()[0]
                s.close()
            except:
                pass

        # Method 3: ultra fallback
        if not auto_ip:
            print("Could not detect local victim automatically.")
            return None

        print("Detected local victim:", auto_ip)
        subnet = ipaddress.ip_network(auto_ip + "/24", strict=False)
        print("Using subnet:", subnet)
        return subnet

    # MANUAL INPUT (Subnet)
    if "/" in raw:
        try:
            return ipaddress.ip_network(raw, strict=False)
        except:
            print("Invalid subnet format.")
            return None

    # MANUAL INPUT (Single IP = /24)
    try:
        ip = ipaddress.ip_address(raw)
        subnet = ipaddress.ip_network(str(ip) + "/24", strict=False)
        print("Detected subnet:", subnet)
        return subnet
    except:
        print("Invalid IP or subnet.")
        return None

def ping_host(ip, mode):
    try:
        if mode == "fast":
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        elif mode == "stealth":
            time.sleep(0.40)
            cmd = ["ping", "-c", "1", "-W", "2", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        out = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out == 0
    except:
        return False


def resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "unknown"


def worker(ip, mode, results):
    if ping_host(ip, mode):
        name = resolve_name(ip)
        results.append((ip, name))


def threaded_ping_sweep(net, mode, results):
    threads = []
    for ip in net.hosts():
        t = threading.Thread(target=worker, args=(str(ip), mode, results))
        t.start()
        threads.append(t)

        if mode == "stealth":
            time.sleep(0.15)

    for t in threads:
        t.join()


def generate_network_report(target, results, subnet, mode):
    folder = os.path.join(REPORTS_DIR, target)
    if not os.path.isdir(folder):
        os.makedirs(folder)

    txt = os.path.join(folder, "report.txt")
    js = os.path.join(folder, "report.json")

    with open(txt, "w") as f:
        f.write("NETWORK SCAN REPORT\n")
        f.write("Target: " + target + "\n")
        f.write("Subnet: " + str(subnet) + "\n")
        f.write("Mode: " + mode + "\n")
        f.write("Alive hosts:\n")
        for ip, name in results:
            f.write(ip + "    " + name + "\n")

    import json
    with open(js, "w") as f:
        json.dump({
            "target": target,
            "subnet": str(subnet),
            "mode": mode,
            "alive": [{"ip": ip, "hostname": name} for ip, name in results]
        }, f, indent=4)


def network_scanner_flow(learning):
    print("BIG NETWORK ENERGY gonna touch ya ports)")
    print("---------------------------------------")

    subnet = ask_for_subnet()
    if not subnet:
        pause()
        return

    print("Subnet:", subnet)

    print("Select mode:")
    print("1) Fast and Loud")
    print("2) Stealth shhhh we ninjas")
    print("3) Hybrid fast and stealthy")

    mc = input("Mode: ").strip()
    if mc == "1":
        mode = "fast"
    elif mc == "2":
        mode = "stealth"
    else:
        mode = "hybrid"

    print("The subnet is being watched dont wait around.... ")

    results = []
    threaded_ping_sweep(subnet, mode, results)

    print("\nAlive hosts:")
    for ip, name in results:
        print(ip, "   ", name)

    tgt = "netscan_" + str(subnet).replace("/", "_")
    generate_network_report(tgt, results, subnet, mode)

    print("\nReport saved under:", tgt)
    pause()

#------------------------------------------------------------------------#
# ---------------- Super Host Analysis (Health, Risk, Trends, Tips) ----------------
import math

def super_host_analysis_flow(learning):
    """
    Aggregate saved reports and produce:
      - health summary
      - risk score (0-100)
      - trend comparison vs last summary
      - actionable recommendations
    Saves: summary_analysis.json, summary_analysis.txt in the target report folder.
    """
    if learning:
        print(Y + "Learning: Super Host Analysis aggregates existing saved reports and makes human recommendations." + RST)
        time.sleep(1)

    target = input("Enter target folder name or hostname (as shown in Reports): ").strip()
    if not target:
        print(R + "No target provided." + RST)
        return

    rdir = os.path.join(REPORTS_DIR, target)
    if not os.path.isdir(rdir):
        print(R + "Report folder not found: " + rdir + RST)
        return

    progress_bar("Assembling data", duration=2)

    # helper - safe JSON loader
    def _load(fn):
        p = os.path.join(rdir, fn)
        if os.path.isfile(p):
            try:
                with open(p, "r", errors="ignore") as f:
                    return json.load(f)
            except:
                return None
        return None

    # load common reports (best-effort)
    tls = _load("tls_cert.json") or _load("tls_cert_report.json")
    http = _load("http_header_report.json") or _load("http_headers.json") or _load("http_headers_report.json")
    whois = _load("whois.json")
    nmap = _load("nmap_lite.json") or _load("nmap.json")
    port_timing = _load("port_timing.json")
    smart = _load("smart_recon.json")
    subdomains = _load("subdomains.json")
    dir_probe = _load("dir_probe.json")
    integrity_log = _load(".kaptainovi_vault_log.json") or _load("integrity_log.json") or _load(".kaptainovi_vault_log.json")
    previous_summary = _load("summary_analysis.json")
    last_host_summary = _load("summary.json") or _load("summary.txt")  # fallback

    # Begin aggregated summary
    agg = {
        "target": target,
        "generated": datetime.utcnow().isoformat(),
        "data": {},
        "risk": None,
        "tips": [],
        "trend": {}
    }

    # TLS: extract key fields
    if tls:
        # multiple formats: support both cert dict and top-level dict
        cert = tls.get("cert") if isinstance(tls, dict) and tls.get("cert") else tls
        try:
            sans = cert.get("subjectAltName") if isinstance(cert, dict) else None
            # normalize SANs to flat list if necessary
            if isinstance(sans, list):
                san_list = [x[1] if isinstance(x, list) and len(x) >= 2 else x for x in sans]
            else:
                san_list = cert.get("san") or []
        except:
            san_list = []
        valid_from = cert.get("notBefore") if isinstance(cert, dict) else None
        valid_to   = cert.get("notAfter") if isinstance(cert, dict) else None
        issuer = cert.get("issuer") if isinstance(cert, dict) else None
        agg["data"]["tls"] = {"issuer": issuer, "valid_from": valid_from, "valid_to": valid_to, "sans": san_list}
    else:
        agg["data"]["tls"] = None

    # HTTP: headers and status
    http_summary = {}
    if http:
        chain = http if isinstance(http, list) else http.get("redirect_chain") or http.get("headers") or http
        if isinstance(chain, list) and chain:
            first = chain[0]; last = chain[-1]
            headers = last.get("headers", {}) if isinstance(last, dict) else {}
            http_summary["initial_status"] = first.get("status")
            http_summary["final_status"] = last.get("status")
            http_summary["server"] = headers.get("Server") or headers.get("server")
            http_summary["hsts"] = bool(headers.get("Strict-Transport-Security") or headers.get("strict-transport-security"))
            http_summary["csp"] = bool(headers.get("Content-Security-Policy"))
        else:
            http_summary = {}
    agg["data"]["http"] = http_summary or None

    # WHOIS
    if whois:
        registrar = whois.get("registrar") or whois.get("Registrar")
        created = whois.get("creation_date") or whois.get("created")
        expires = whois.get("expiration_date") or whois.get("expires")
        agg["data"]["whois"] = {"registrar": registrar, "created": created, "expires": expires}
    else:
        agg["data"]["whois"] = None

    # Ports & port timing
    open_ports = []
    if nmap and isinstance(nmap, dict):
        for k,v in nmap.items():
            try:
                p = int(k)
            except:
                continue
            if isinstance(v, dict) and v.get("open"):
                open_ports.append(p)
            elif isinstance(v, str) and "open" in v.lower():
                open_ports.append(p)
    if port_timing and isinstance(port_timing, dict):
        timing_open = port_timing.get("summary", {}).get("open_ports") or port_timing.get("summary", {}).get("open_ports", [])
        # handle both list of ints or list of tuples
        if isinstance(timing_open, list):
            open_ports = sorted(set(open_ports + [int(x) if not isinstance(x, (list,tuple)) else int(x[0]) for x in timing_open]))
    agg["data"]["open_ports"] = sorted(open_ports)

    # banners
    agg["data"]["banners"] = smart.get("banners") if smart else None

    # subdomains
    agg["data"]["subdomains"] = subdomains.get("found") if isinstance(subdomains, dict) else subdomains

    # dir probe
    agg["data"]["dir_probe"] = dir_probe.get("results") if isinstance(dir_probe, dict) else dir_probe

    # Integrity changes recent?
    changed_files = []
    if integrity_log and isinstance(integrity_log, list):
        # count recent changes in last 30 entries
        changed_files = [e.get("file") for e in integrity_log[-30:]]
    agg["data"]["recent_integrity_changes"] = changed_files

    # ---------------- Risk Scoring (simple weighted heuristic) ----------------
    # Start at 100 (safe) then subtract weighted penalties; final risk = clamp(0,100 - penalties)
    penalty = 0
    # open ports penalty
    op = len(agg["data"]["open_ports"]) if agg["data"]["open_ports"] else 0
    penalty += min(op * 6, 40)   # each open port costs up to 6 points, cap 40
    # risky ports extra penalty
    risky_set = {21,23,445,3306,3389,5900,6379,5432,1521}
    risky_found = [p for p in agg["data"]["open_ports"] if p in risky_set]
    penalty += len(risky_found) * 8
    # missing HTTP security headers
    if agg["data"].get("http"):
        if not agg["data"]["http"].get("hsts"):
            penalty += 8
        if not agg["data"]["http"].get("csp"):
            penalty += 6
    else:
        penalty += 4  # no HTTP data
    # TLS issues: missing cert or expiring soon
    tls_info = agg["data"].get("tls")
    if not tls_info:
        penalty += 10
    else:
        vt = tls_info.get("valid_to")
        if vt:
            try:
                # best-effort year parse
                if isinstance(vt, str) and len(vt) >= 4 and vt[:4].isdigit():
                    exp_year = int(vt[:4])
                    years_left = exp_year - datetime.utcnow().year
                    if years_left <= 0:
                        penalty += 25
                    elif years_left <= 1:
                        penalty += 12
                else:
                    # unknown format -> small penalty
                    penalty += 2
            except:
                penalty += 2
    # recent integrity changes
    if changed_files:
        penalty += min(len(changed_files) * 2, 12)

    # cap penalty
    penalty = min(penalty, 90)
    risk_score = max(0, min(100, 100 - penalty))
    agg["risk"] = {"score": risk_score, "penalty": penalty}



    # ---------------- Generate automated tips & recommendations ----------------
    tips = []
    # Open ports advice
    if agg["data"]["open_ports"]:
        tips.append({"title":"Open ports detected", "suggestion":f"{len(agg['data']['open_ports'])} open port(s): {agg['data']['open_ports']}. Confirm which should be internet-accessible."})
        for p in agg["data"]["open_ports"]:
            if p in risky_set:
                tips.append({"title":f"Risky port {p}", "suggestion":f"Port {p} is commonly exploited. Verify service config, authenticate, or firewall it."})
    else:
        tips.append({"title":"No open ports recorded", "suggestion":"No open ports found in saved data. If you expected services, run port timing / nmap from a different vantage."})

    # HTTP/TLS tips
    if agg["data"].get("http"):
        if not agg["data"]["http"].get("hsts"):
            tips.append({"title":"HSTS missing", "suggestion":"Enable HTTP Strict Transport Security (HSTS) to reduce downgrade risks."})
        if not agg["data"]["http"].get("csp"):
            tips.append({"title":"CSP missing", "suggestion":"Consider setting a Content-Security-Policy to reduce XSS risk."})
        srv = (agg["data"]["http"].get("server") or "").lower()
        if "cloudflare" in srv or "cloudflare" in str(agg["data"].get("banners", "")).lower():
            tips.append({"title":"Behind a CDN", "suggestion":"Responses indicate a CDN. Origin IPs may be hidden - use origin-aware checks if needed."})
    else:
        tips.append({"title":"No HTTP data", "suggestion":"Run HTTP Header Inspector to capture headers and HSTS/CSP settings."})

    if agg["data"].get("tls") is None:
        tips.append({"title":"No TLS data", "suggestion":"Run TLS capture for certificate details and revocation endpoints."})
    else:
        # advise on .onion presence
        sans = agg["data"]["tls"].get("sans") or []
        if any(".onion" in str(s) for s in sans):
            tips.append({"title":"Onion service present", "suggestion":"Certificate includes .onion name - operator likely offers Tor service; useful for privacy-centered access."})

    # integrity changes
    if changed_files:
        tips.append({"title":"Integrity change history", "suggestion":f"{len(changed_files)} recent integrity log entries found. Review changes for unexpected modifications."})

    # summarize WHOIS
    if agg["data"].get("whois"):
        if not agg["data"]["whois"].get("registrar"):
            tips.append({"title":"Whois limited", "suggestion":"WHOIS appears limited or private. Domain privacy may be enabled."})

    tips.append({"title":"Monitoring", "suggestion":"Consider scheduling periodic automatic checks and enable alerts for cert expiry and integrity changes."})

    agg["tips"] = tips

    # ---------------- Trend comparison vs previous_summary (if any) ----------------
    trend = {"changed": False, "notes": []}
    if previous_summary and isinstance(previous_summary, dict):
        # compare open ports
        prev_ports = previous_summary.get("data", {}).get("open_ports", [])
        curr_ports = agg["data"].get("open_ports", [])
        if set(prev_ports) != set(curr_ports):
            trend["changed"] = True
            added = set(curr_ports) - set(prev_ports)
            removed = set(prev_ports) - set(curr_ports)
            if added:
                trend["notes"].append(f"New open ports since last run: {sorted(list(added))}")
            if removed:
                trend["notes"].append(f"Ports closed since last run: {sorted(list(removed))}")
        # risk trend
        prev_risk = previous_summary.get("risk", {}).get("score")
        if isinstance(prev_risk, (int,float)):
            delta = agg["risk"]["score"] - prev_risk
            trend["notes"].append(f"Risk score change: {prev_risk} -> {agg['risk']['score']} (delta {delta:+})")
    agg["trend"] = trend

    # ---------------- Save report ----------------
    out_json = os.path.join(rdir, "summary_analysis.json")
    out_txt  = os.path.join(rdir, "summary_analysis.txt")
    try:
        with open(out_json, "w") as jf:
            json.dump(agg, jf, indent=2)
        # human readable
        lines = []
        lines.append(f"Super Host Analysis: {target}")
        lines.append(f"Generated: {agg['generated']}")
        lines.append(f"Risk Score: {agg['risk']['score']} / 100  (penalty {agg['risk']['penalty']})")
        lines.append("")
        lines.append("Top findings:")
        for t in agg["tips"][:8]:
            lines.append(f" - {t['title']}: {t['suggestion']}")
        lines.append("")
        if agg["trend"]["notes"]:
            lines.append("Trend:")
            for n in agg["trend"]["notes"]:
                lines.append(f" - {n}")
        lines.append("")
        with open(out_txt, "w") as tf:
            tf.write("\n".join(lines))
        print(G + f"Saved analysis to: {out_json} and {out_txt}" + RST)
        log("SUPER_ANALYSIS " + target)
    except Exception as e:
        print(R + "Failed to save analysis: " + str(e) + RST)

    # Display concise result
    print("\n" + ("=" * 60))
    print(f"Super Analysis for {target}")
    print(f"Risk Score: {agg['risk']['score']} / 100")
    print("Top suggestions:")
    for t in agg["tips"][:6]:
        print(f" - {t['title']}: {t['suggestion']}")
    if agg["trend"]["notes"]:
        print("\nTrend notes:")
        for n in agg["trend"]["notes"]:
            print(" -", n)
    print("\nFull report saved to the report folder.")
    input("\nPress Enter to continue...")







# ---------------- Vulnerability Indicator Tester (safe, non-exploit) ----------------
import re
import ssl
import socket
import json
import time

# Lightweight version parser from banners (best-effort)
def _extract_version(text):
    # common patterns like "nginx/1.14.2", "Apache/2.2.3", "OpenSSH_7.4"
    if not text:
        return None
    try:
        m = re.search(r"([A-Za-z0-9_\-\.]+)[/\s]v?(\d+(?:\.\d+){0,3})", text)
        if m:
            return (m.group(1).lower(), m.group(2))
    except:
        pass
    return None

# Comparer for semantic-ish versions (major only)
def _major_version(version_str):
    try:
        parts = str(version_str).split(".")
        return int(parts[0]) if parts and parts[0].isdigit() else None
    except:
        return None

def vuln_tester_flow(learning):
    """
    Safe vulnerability indicator tester: -  non-destructive checks only (HEAD/GET, safe TCP connect, banner peek) - loads past analysis and re-checks candidate issues - flags possible weak/old software versions (suggests vendor advisory lookup) - saves vuln_test.json and vuln_test.txt into the report folder
    IMPORTANT: does NOT perform exploit actions. Requires explicit permission confirmation.
    """
    if learning:
        print(Y + "Learning: Vulnerability tester runs safe checks to identify indicators of potential risk. No exploits are run." + RST)
        time.sleep(1)

    target = input("Enter target report folder name or hostname (as in Reports): ").strip()
    if not target:
        print(R + "No target provided." + RST)
        return

    rdir = os.path.join(REPORTS_DIR, target)
    if not os.path.isdir(rdir):
        print(R + "Report folder not found: " + rdir + RST)
        return

    # Permission check
    confirm = input("Type 'I HAVE PERMISSION' to confirm you are authorized to test this target: ").strip()
    if confirm.lower() != "i have permission":
        print(R + "Permission not confirmed - aborting." + RST)
        return

    # Load previous analysis if available
    analysis = None
    try:
        with open(os.path.join(rdir, "summary_analysis.json"), "r") as f:
            analysis = json.load(f)
    except:
        analysis = None

    # Assemble targets to re-check
    host = target
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except Exception as e:
        # not fatal - we'll continue with host name
        resolved_ip = None

    # Basic list of ports to probe (from analysis if present)
    ports = []
    if analysis and isinstance(analysis.get("data", {}).get("open_ports"), list):
        ports = analysis["data"]["open_ports"]
    else:
        ports = [80, 443, 22, 21, 3306, 3389, 5900, 5432]

    results = {
        "target": target,
        "resolved_ip": resolved_ip,
        "timestamp": datetime.utcnow().isoformat(),
        "tls": {},
        "http": {},
        "service_banners": {},
        "dir_probe": {},
        "indicators": [],   # findings with severity: INFO/WARN/CRITICAL
    }

    # ----- TLS check (port 443) -----
    def _tls_check(hostname):
        out = {"ok": False, "notBefore": None, "notAfter": None, "san": None, "issuer": None, "notes": []}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                    cert = ss.getpeercert()
                    out["notBefore"] = cert.get("notBefore")
                    out["notAfter"] = cert.get("notAfter")
                    out["san"] = cert.get("subjectAltName")
                    out["issuer"] = cert.get("issuer")
                    out["ok"] = True
                    # expiry heuristic
                    na = out["notAfter"]
                    if na:
                        # if OpenSSL format like "Mar 25 04:43:22 2026 GMT", try parse year
                        yr = None
                        try:
                            m = re.search(r"\b(19|20)\d{2}\b", str(na))
                            if m:
                                yr = int(m.group(0))
                        except:
                            yr = None
                        if yr:
                            if yr <= datetime.utcnow().year:
                                out["notes"].append(("CERT_EXPIRED", "Certificate appears expired (or expiry year <= current year)."))
                            elif yr - datetime.utcnow().year <= 1:
                                out["notes"].append(("CERT_EXPIRES_SOON", "Certificate expires within ~1 year; consider monitoring/renewal."))
        except Exception as e:
            out["notes"].append(("TLS_ERROR", f"TLS check error: {e}"))
        return out

    print(Y + "Running TLS check..." + RST)
    tls_res = _tls_check(host)
    results["tls"] = tls_res
    # indicators from TLS
    for tag, msg in tls_res.get("notes", []):
        sev = "WARN" if tag != "CERT_EXPIRED" else "CRITICAL"
        results["indicators"].append({"type":"tls", "tag":tag, "severity":sev, "message":msg})

    # ----- HTTP header check (HEAD)  -----
    def _http_head(hostname, use_tls=False):
        out = {"ok": False, "status": None, "headers": {}, "notes": []}
        port = 443 if use_tls else 80
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=4) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                        ss.sendall(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                        data = ss.recv(4096).decode(errors="ignore")
            else:
                with socket.create_connection((hostname, port), timeout=4) as sock:
                    sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                    data = sock.recv(4096).decode(errors="ignore")
            lines = [ln for ln in data.splitlines() if ln.strip()]
            if lines:
                status_line = lines[0]
                parts = status_line.split()
                if len(parts) >= 2:
                    try:
                        out["status"] = int(parts[1])
                    except:
                        out["status"] = status_line
                headers = {}
                for ln in lines[1:]:
                    if ":" in ln:
                        k,v = ln.split(":",1)
                        headers[k.strip()] = v.strip()
                out["headers"] = headers
                out["ok"] = True
                # quick header checks
                if not any(k.lower() == "strict-transport-security" for k in headers.keys()):
                    out["notes"].append(("HSTS_MISSING","HSTS header missing"))
                if not any("content-security-policy" in k.lower() for k in headers.keys()):
                    out["notes"].append(("CSP_MISSING","CSP header missing"))
        except Exception as e:
            out["notes"].append(("HTTP_ERROR", f"HTTP HEAD failed: {e}"))
        return out

    print(Y + "Checking HTTPS HEAD then HTTP fallback..." + RST)
    http_res = _http_head(host, use_tls=True)
    if not http_res["ok"]:
        http_res = _http_head(host, use_tls=False)
    results["http"] = http_res
    for tag,msg in http_res.get("notes", []):
        sev = "WARN" if "MISSING" in tag else "INFO"
        results["indicators"].append({"type":"http","tag":tag,"severity":sev,"message":msg})

    # ----- Banner grabs for ports ----- (non-intrusive small recv)
    def _peek_banner(hostname, port, timeout=1.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((hostname, port))
            try:
                data = s.recv(512)
            except:
                data = b""
            s.close()
            if data:
                return data.decode(errors="ignore").strip().splitlines()[:4]
            return []
        except:
            return []

    print(Y + "Peeking service banners..." + RST)
    banner_map = {}
    for p in sorted(set(ports)):
        b = _peek_banner(host if resolved_ip is None else resolved_ip, p)
        banner_map[str(p)] = b
        # parse for versions and indicators
        if b:
            txt = " ".join(b).lower()
            ver = _extract_version(txt)
            if ver:
                svc, verstr = ver
                maj = _major_version(verstr)
                note = None
                # Simple heuristics for "old" major versions (conservative)
                if svc in ("apache", "httpd"):
                    if maj and maj < 2:
                        note = ("OLD_APACHE", f"Apache major version {maj} detected; older branches may be vulnerable - check vendor advisories.")
                if svc == "nginx":
                    if maj and maj < 1:
                        note = ("OLD_NGINX", f"Nginx major version {maj} detected; verify updates.")
                if svc.startswith("openssh") or "openssh" in txt:
                    # parse openssh version
                    try:
                        m = re.search(r"openssh[_\s]?(\d+)\.?(\d+)?", txt)
                        if m:
                            o_maj = int(m.group(1))
                            if o_maj < 7:
                                note = ("OLD_OPENSSH", "OpenSSH major version <7 detected; consider upgrade.")
                    except:
                        pass
                if note:
                    results["indicators"].append({"type":"banner","port":p,"tag":note[0],"severity":"WARN","message":note[1]})
    results["service_banners"] = banner_map

    # ----- Light directory probe (safe) -----
    print(Y + "Running light directory probe (HEAD/GET safe checks)..." + RST)
    probe_paths = ["/robots.txt","/admin","/login","/.git/","/backup.zip","/config.php","/wp-admin/"]
    dir_found = {}
    for path in probe_paths:
        found = False
        status = None
        try:
            # use https if HTTPS ok
            using_tls = results["http"].get("ok") and str(results["http"].get("status","")).startswith("2")
            if using_tls:
                ctx = ssl.create_default_context()
                with socket.create_connection((host,443), timeout=4) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        ss.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                        data = ss.recv(2048).decode(errors="ignore")
            else:
                with socket.create_connection((host,80), timeout=4) as sock:
                    sock.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                    data = sock.recv(2048).decode(errors="ignore")
            if data:
                first = data.splitlines()[0] if data.splitlines() else ""
                if "HTTP" in first:
                    try:
                        status = int(first.split()[1])
                    except:
                        status = first
                if status and (200 <= int(status) < 400):
                    found = True
        except Exception as e:
            # ignore but record
            status = f"err:{e}"
        dir_found[path] = {"found": found, "status": status}
        if found:
            results["indicators"].append({"type":"dir","path":path,"severity":"WARN","message":f"Accessible path {path} returned status {status}. Review exposure."})

    results["dir_probe"] = dir_found

    # ----- Heuristic summary & safe remediation guidance -----
    # Consolidate indicators and add recommendations (no exploit instructions)
    def _recommend_for_indicator(ind):
        t = ind.get("tag") or ind.get("type")
        if t in ("CERT_EXPIRED","CERT_EXPIRES_SOON"):
            return "Renew or replace TLS certificate; consider automation (ACME) and monitoring."
        if t == "HSTS_MISSING":
            return "Enable HSTS with an appropriate max-age after confirming TLS is correct."
        if t == "CSP_MISSING":
            return "Add a Content-Security-Policy to reduce XSS risk; test in report-only mode first."
        if t.startswith("OLD_") or t in ("OLD_OPENSSH",):
            return "Check vendor advisories for the detected software version and apply updates/patches as needed."
        if t == "TLS_ERROR":
            return "Investigate TLS availability; ensure port 443 is reachable and certificate chain is valid."
        if t == "HTTP_ERROR":
            return "Investigate web server response and firewall rules."
        if t == "dir":
            return "Remove or restrict access to sensitive directories, add auth or server rules, and avoid storing backups in web root."
        return "Review the finding and consult vendor/security advisories."

    # Attach recommendations to each indicator
    for ind in results["indicators"]:
        rec = _recommend_for_indicator(ind)
        ind["recommendation"] = rec

    # ----- Save output -----
    out_json = os.path.join(rdir, "vuln_test.json")
    out_txt  = os.path.join(rdir, "vuln_test.txt")
    try:
        with open(out_json, "w") as jf:
            json.dump(results, jf, indent=2)
        # human readable
        lines = []
        lines.append(f"Vulnerability Indicator Test: {target}")
        lines.append(f"Generated: {results['timestamp']}")
        lines.append(f"Resolved IP: {results.get('resolved_ip')}")
        lines.append("")
        lines.append("Quick Indicators (severity suggested):")
        for ind in results["indicators"]:
            sev = ind.get("severity","INFO")
            lines.append(f" - [{sev}] {ind.get('type') or ind.get('tag')} : {ind.get('message')}")
            if ind.get("recommendation"):
                lines.append(f"    => Recommendation: {ind.get('recommendation')}")
        lines.append("")
        lines.append("Directory probe results:")
        for p,info in results["dir_probe"].items():
            lines.append(f" - {p}: found={info['found']} status={info['status']}")
        lines.append("")
        with open(out_txt, "w") as tf:
            tf.write("\n".join(lines))
        print(G + f"Saved vulnerability indicator test to: {out_json} and {out_txt}" + RST)
        log("VULN_TEST " + target)
    except Exception as e:
        print(R + "Failed saving vuln test: " + str(e) + RST)

    # Print concise interactive summary
    print("\n== Vulnerability Indicators Summary ==")
    for ind in results["indicators"][:8]:
        print(f" - [{ind.get('severity')}] {ind.get('message')}")
    print("\nSee full report files in:", rdir)
    input("\nPress Enter to continue...")  
      
# --------------------Small utilities ----------------
def list_reports_flow():
    print("Reports directory:", REPORTS_DIR)
    for root, dirs, files in os.walk(REPORTS_DIR):
        if root == REPORTS_DIR:
            for d in dirs:
                print(" -", d)
    input("\nPress Enter to continue...")  # optional, or remove if you want open view

def view_report_flow():
    target = input("Enter report folder name (as shown in list): ").strip()
    if not target:
        return
    rdir = os.path.join(REPORTS_DIR, target)
    if not os.path.isdir(rdir):
        print(R + "Report not found." + RST)
        return
    files = os.listdir(rdir)
    print(G + "Files in report:" + RST)
    for f in files:
        print(" -", f)
    fn = input("Enter file to view (report.txt or report.json): ").strip()
    path = os.path.join(rdir, fn)
    if not os.path.isfile(path):
        print(R + "File not found." + RST)
        return
    with open(path, "r", errors="ignore") as fh:
        print("\n" + fh.read())
    print(G + "\nPress Ctrl+X to exit view" + RST)
    try:
        while True:
            k = input()
    except KeyboardInterrupt:
        return

# ---------------- Main menu ----------------
def main():
    learning = True
    while True:
        header("KAPTAINOVI - LITE (Phase 1)")
        print("1) Phone lookup")
        print("2) IP / Host recon")
        print("3) Smart Recon (Banner analysis)")
        print("4) Trace and Map (traceroute)")
        print("5) who is(IP/Webadd owner look up") 
        print("6) Http/Headers inspector (looks 4 things)")
        print("7) TLS/SSL (Cerificate Checker)")
        print("8) DNS ToolKit (Lookups + AXFR)")
        print("9) SubDomain Enumerator (wordlist)")
        print("10) HTTP Directory Probe (lite)")
        print("11) SMTP open relay test(careful)")  
        print("12) Service Fingerprint (save banner")
        print("13) Porting and Recon (high octane like NOS)")
        print("14) Search Reports ( name/email)")
        print("15) List Repors")
        print("16) View Reports")
        print("17) Clean Repors")
        print("18) The Final Super Report (Everything you need to know)")
        print("19) Host Summary")
        print("20) Integrity Vault")
        print("21) New Deep scan")
        print("s) Network Scanner (fast stealth hybrid)")
        print("*) Tool The one")
        print("l) Toggle learning mode (current: " + ("ON" if learning else "OFF") + ")")
        print("x) Exit")
        choice = input("Choice: ").strip().lower()
        if choice == "1":
            phone_lookup_flow(learning)
        elif choice == "2":
            ip_recon_flow(learning)
        elif choice == "3":
            smart_recon_flow(learning)
        elif choice == "4":
            trace_map_flow(learning)
        elif choice == "5":
            whois_lookup_flow(learning)
        elif choice == "6":
            http_header_inspector_flow(learning)
        elif choice == "7":
            tls_cert_flow(learning)
        elif choice == "8":
            dns_toolkit_flow(learning)
        elif choice == "9":
            subdomain_enum_flow(learning)   
        elif choice == "10":
            http_dir_probe_flow(learning)
        elif choice == "11":
            smtp_relay_test_flow(learning)
        elif choice == "12":
            service_fingerprint_flow(learning)
        elif choice == "13":
            port_timing_flow(learning)
        elif choice == "14":
            search_reports_flow(learning)
        elif choice == "15":
            list_reports_flow()
        elif choice == "16":
            view_report_flow()
        elif choice == "17":
            clean_reports_flow(learning)
        elif choice == "18":
            super_host_analysis_flow(learning)
        elif choice == "19":
            host_summary_flow(learning)
        elif choice == "20":
            integrity_vault_flow(learning)
        elif choice == "21":
	        new_network_scan_flow(subnet="10.0.0.0/24")        
        elif choice == "s":
            network_scanner_flow(learning)
        elif choice == "*":
            vuln_tester_flow(learning)
        elif choice == "l":
            learning = not learning
            print("Learning mode now", "ON" if learning else "OFF")
            log("LEARNING toggled " + str(learning))
            pause()
        elif choice == "x":
            print("Exiting...")
            log("EXIT")
            break
        else:
            print("Unknown choice")
            pause()

if __name__ == "__main__":
    try:
        welcome_screen()
        main()
    except KeyboardInterrupt:
        print("\nExiting...")

