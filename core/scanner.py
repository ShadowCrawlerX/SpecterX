import os
import dns.resolver
from datetime import datetime
from utils.reporter import write_html_section


def run_subdomain_scan():
    print("\n🌐 [Subdomain Scanner]")
    domain = input("Enter a domain (e.g. example.com): ").strip()
    if not domain:
        print("No domain entered.")
        input("Press Enter to return...")
        return

    wordlist_path = "wordlists/subdomains.txt"
    if not os.path.exists(wordlist_path):
        print(f"[❌] Wordlist not found at {wordlist_path}")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Scanning subdomains of: {domain}\n")
    found = []

    try:
        with open(wordlist_path, "r") as f:
            for word in f:
                sub = word.strip()
                full_domain = f"{sub}.{domain}"
                try:
                    answers = dns.resolver.resolve(full_domain, "A")
                    ips = [r.address for r in answers]
                    print(f"[✅] {full_domain} → {', '.join(ips)}")
                    found.append((full_domain, ips))
                except dns.resolver.NXDOMAIN:
                    pass
                except dns.resolver.NoAnswer:
                    pass
                except Exception as e:
                    print(f"[⚠️] {full_domain} error: {e}")
    except Exception as e:
        print(f"[🔥] Failed to scan: {e}")
    lines = [f"{full} → {', '.join(ips)}" for full, ips in found]  
    write_html_section("subdomain scanner",lines)
    print(f"\n[✔️] Scan complete. Found {len(found)} subdomains.")
    input("Press Enter to return...")

import socket
import threading
from queue import Queue
import json

def run_port_scan():
    print("\n📡 [Port Scanner]")
    target = input("Enter target IP or domain: ").strip()
    port_range = input("Enter port range (e.g. 1-9000): ").strip() or "1-1024"

    try:
        start_port, end_port = map(int, port_range.split("-"))
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            raise ValueError
    except ValueError:
        print("[❌] Invalid port range.")
        input("Press Enter to return...")
        return

    try:
        with open("data/exploits.json", "r") as f:
            exploit_db = json.load(f)
    except:
        exploit_db = {}
        print("[⚠️] Exploit DB not loaded.")

    print(f"\n[🔍] Scanning {target} from port {start_port} to {end_port}...\n")
    open_ports = []

    # Threaded worker function
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
                if result == 0:
                    try:
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except:
                        banner = "No banner"
                    match = None
                    for known_banner in exploit_db:
                        if known_banner in banner:
                            match = exploit_db[known_banner]
                            break
                    if match:
                     print(f"[⚠️] Port {port} → {banner}")
                     print(f"     ↪ CVE: {match['cve']}")
                     print(f"     ↪ {match['desc']}")
                     print(f"     ↪ Link: {match['link']}")
                    else:
                     print(f"[✅] Port {port} open → {banner}")
                    open_ports.append((port, banner))
        except:
            pass

    # Thread manager
    def threader():
        while True:
            port = q.get()
            scan_port(port)
            q.task_done()

    # Setup queue and threads
    q = Queue()
    thread_count = 100  # You can adjust this
    for _ in range(thread_count):
        t = threading.Thread(target=threader, daemon=True)
        t.start()

    for port in range(start_port, end_port + 1):
        q.put(port)

    q.join()  # Wait for all threads to finish
    # Format output for HTML report
    lines = []
    cve_lines = []
    for port, banner in open_ports:
        lines.append(f"{target}:{port} → {banner}")
        for known_banner in exploit_db:
            if known_banner in banner:
                match = exploit_db[known_banner]
                cve_lines.append(
                f"{target}:{port} ({banner}) → CVE: {match['cve']} | {match['desc']} | {match['link']}"
            )
            break

    if lines:
        write_html_section("Port Scanner", lines)
    if cve_lines:
        write_html_section("Exploit Matcher", cve_lines)
    print("[💾] Appended to report.html")


    print(f"\n[✔️] Scan complete. Found {len(open_ports)} open ports.")
    input("Press Enter to return...")

import requests
import re

def run_web_fingerprint():
    print("\n🌐 [Web Fingerprinting]")
    url = input("Enter target URL (e.g. http://example.com): ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    print(f"\n[🔍] Probing: {url}\n")

    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers

        # Print HTTP status code
        print(f"[🧾] Status Code: {resp.status_code}")

        # Title
        title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "No title found"
        print(f"[📘] Page Title: {title}")

        # Server header
        server = headers.get("Server", "Unknown")
        print(f"[🖥️ ] Server Header: {server}")

        # X-Powered-By
        powered_by = headers.get("X-Powered-By", "Unknown")
        print(f"[⚙️ ] X-Powered-By: {powered_by}")

        # CMS detection
        if "wp-content" in resp.text or "wp-includes" in resp.text:
            print("[🧩] CMS Detected: WordPress")
        elif "Joomla" in resp.text or "joomla.org" in resp.text:
            print("[🧩] CMS Detected: Joomla")
        elif "drupal" in resp.text:
            print("[🧩] CMS Detected: Drupal")
        else:
            print("[❓] CMS: Not detected")

    except requests.exceptions.RequestException as e:
        print(f"[❌] Request failed: {e}")

    cms = "Unknown"
    if "wp-content" in resp.text or "wp-includes" in resp.text:
        cms = "WordPress"
    elif "Joomla" in resp.text or "joomla.org" in resp.text:
        cms = "Joomla"
    elif "drupal" in resp.text:
        cms = "Drupal"

    lines = [
        f"URL: {url}",
        f"Status: {resp.status_code}",
        f"Title: {title}",
        f"Server: {server}",
        f"X-Powered-By: {powered_by}",
        f"CMS: {cms}"
        ]   
    write_html_section("Web Fingerprinter", lines)
    print("[💾] Appended to report.html")
    input("\nPress Enter to return...")


def run_lan_ip_scan():
    from utils.reporter import write_html_section
    import netifaces, ipaddress, subprocess, platform

    print("\n🌐 [LAN IP Scanner]")

    try:
        gateway = netifaces.gateways()['default'][netifaces.AF_INET][1]
        iface_data = netifaces.ifaddresses(gateway)[netifaces.AF_INET][0]
        local_ip = iface_data['addr']
        netmask = iface_data['netmask']
        interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
        subnet = interface.network
        print(f"[🧠] Local IP: {local_ip}")
        print(f"[🌐] Netmask : {netmask}")
        print(f"[🔍] Scanning subnet: {subnet}")
    except Exception as e:
        print(f"[❌] Failed to detect network: {e}")
        input("Press Enter to return...")
        return

    print("\n[⚡] Pinging subnet... (this may take a few seconds)")
    # Ping sweep to populate ARP cache (some OSes need this)
    for ip in subnet.hosts():
        ip_str = str(ip)
        if platform.system().lower() == "windows":
            subprocess.run(["ping", "-n", "1", "-w", "300", ip_str], stdout=subprocess.DEVNULL)
        else:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip_str], stdout=subprocess.DEVNULL)

    print("[📡] Collecting live devices from ARP table...\n")
    devices = []

    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output("arp -a", shell=True).decode()
            for line in output.splitlines():
                if "-" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, mac = parts[0], parts[1]
                        devices.append((ip, mac))
        else:
            output = subprocess.check_output("arp -a", shell=True).decode()
            for line in output.splitlines():
                if "(" in line:
                    ip = line.split("(")[1].split(")")[0]
                    mac = line.split()[-1]
                    devices.append((ip, mac))
    except Exception as e:
        print(f"[❌] Failed to read ARP table: {e}")
        input("Press Enter to return...")
        return

    if devices:
        for ip, mac in devices:
            print(f"[✅] {ip} → {mac}")
        lines = [f"{ip} → {mac}" for ip, mac in devices]
        write_html_section("LAN IP Scanner", lines)
        print("[💾] Appended to report.html")
    else:
        print("[❌] No live devices found.")

    input("\nPress Enter to return...")


def run():
    print("\n[🔧 Technical Recon]")
    print("[1] Subdomain Scanner")
    print("[2] Port Scanner")
    print("[3] Web Fingerprinter")
    print("[4] LAN IP Scanner")
    print("[5] Back to Main Menu")
    choice = input("Select an option: ").strip()

    if choice == '1':
        run_subdomain_scan()
    elif choice == '2':
        run_port_scan()
    elif choice == '3':
        run_web_fingerprint()
    elif choice == '4':
        run_lan_ip_scan()
