# core/osint.py

import requests
from datetime import datetime
from utils.reporter import write_html_section


platforms = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Telegram": "https://t.me/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter (X)": "https://x.com/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Steam": "https://steamcommunity.com/id/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "DEV.to": "https://dev.to/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Keybase": "https://keybase.io/{}",
    "GitLab": "https://gitlab.com/{}",
    "Flickr": "https://www.flickr.com/people/{}",
}

def check_username(username):
    print(f"\n[🔎] Searching for '{username}' across platforms:\n")
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    for site, url in platforms.items():
        full_url = url.format(username)
        try:
            resp = requests.get(full_url, headers=headers, timeout=6)

            if resp.status_code == 200:
                if site == "Reddit":
                    if "Sorry, nobody on Reddit goes by that name" in resp.text or "suspended" in resp.text:
                        status = f"{site}: Page exists, but user is missing/banned"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "Telegram":
                    if "If you have Telegram" not in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "GitLab":
                    if "Not Found" in resp.text:
                        status = f"{site}: Not found (text check)"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "Keybase":
                    if "We couldn’t find any" in resp.text:
                        status = f"{site}: Not found (text check)"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "Flicker":
                    if "Oops! We can't find that page" in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "HackerNews":
                    if "user not found" in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "TikTok":
                    if "Couldn't find this account" in resp.text or "Page Not Found" in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                else:
                    status = f"{site}: Found → {full_url}"
            elif resp.status_code in [403, 429]:
                status = f"{site}: Rate-limited or blocked (status {resp.status_code})"
            elif resp.status_code == 404:
                status = f"{site}: Not found"
            elif resp.status_code == 400:
                status = f"{site}: Invalid username or bad request"
            else:
                status = f"{site}: Unhandled status {resp.status_code}"
        except requests.exceptions.RequestException as e:
            status = f"{site}: Connection failed - {e}"

        print(f"[{status}]")
        results.append(status)

    write_html_section("Username OSINT", [f"Username: {username}"] + results)
    input("\nPress Enter to return...")


import socket
import dns.resolver
import whois
def run_domain_osint():
    print("\n🌐 [DOMAIN OSINT] Scan")
    domain = input("Enter a domain (e.g. example.com): ").strip()
    if not domain:
        print("No domain provided.")
        return

    print(f"\n[🔍] Scanning: {domain}\n")

    try:
        # WHOIS Info
        print("📄 WHOIS Info:")
        w = whois.whois(domain)
        print(f"  Registrar     : {w.registrar}")
        print(f"  Creation Date : {w.creation_date}")
        print(f"  Expiration    : {w.expiration_date}")
        print(f"  Emails        : {w.emails}")
    except Exception as e:
        print(f"  [!] WHOIS lookup failed: {e}")

    # DNS Records
    try:
        print("\n📡 DNS Records:")
        for record_type in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                print(f"  {record_type} Records:")
                for r in answers:
                    print(f"    → {str(r)}")
            except dns.resolver.NoAnswer:
                print(f"  {record_type}: No records found")
            except dns.resolver.NXDOMAIN:
                print(f"  {record_type}: Domain not found")
            except Exception as e:
                print(f"  {record_type}: Error - {e}")
    except Exception as e:
        print(f"  [!] DNS resolution failed: {e}")

    lines = [f"Domain: {domain}"]
    try:
        w = whois.whois(domain)
        lines.append(f"Registrar: {w.registrar}")
        lines.append(f"Created: {w.creation_date}")
        lines.append(f"Expires: {w.expiration_date}")
        lines.append(f"Emails: {w.emails}")
    except Exception as e:
        lines.append(f"WHOIS failed: {e}")

    lines.append("DNS Records:")
    for record_type in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for r in answers:
                lines.append(f"{record_type}: {r}")
        except Exception as e:
            lines.append(f"{record_type}: Error - {e}")

    write_html_section("Domain OSINT", lines)
    print("[💾] Appended to report.html")

    input("\nPress Enter to return...")

import re
import hashlib

def is_valid_email(email):
    # Simple email regex
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return re.match(pattern, email)

def get_gravatar_url(email):
    # MD5 hash of lowercase trimmed email
    email_clean = email.strip().lower()
    email_hash = hashlib.md5(email_clean.encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?d=404"

def run_email_osint():
    print("\n📧 [EMAIL OSINT]")
    email = input("Enter an email: ").strip()

    if not is_valid_email(email):
        print("[❌] Invalid email format.")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Scanning email: {email}\n")

    # Gravatar Check
    gravatar_url = get_gravatar_url(email)
    try:
        resp = requests.get(gravatar_url, timeout=5)
        if resp.status_code == 200:
            print(f"[🧑‍🎨] Gravatar profile exists → {gravatar_url}")
        elif resp.status_code == 404:
            print("[❌] No Gravatar profile found")
        else:
            print(f"[⚠️ ] Unexpected Gravatar response: {resp.status_code}")
    except Exception as e:
        print(f"[🔥] Gravatar check failed: {e}")

    # MX Records
    domain = email.split('@')[-1]
    print(f"\n📡 MX Records for domain: {domain}")
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        for r in mx_answers:
            print(f"  → {str(r)}")
    except Exception as e:
        print(f"  [!] Failed to get MX records: {e}")

    lines = [f"Email: {email}"]

    # Gravatar result already printed above
    lines.append(f"Gravatar URL: {gravatar_url} (Status: {resp.status_code})")

    lines.append(f"MX Records for {domain}:")
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        for r in mx_answers:
            lines.append(f"→ {r}")
    except Exception as e:
        lines.append(f"[!] Failed to get MX records: {e}")

    write_html_section("Email OSINT", lines)
    print("[💾] Appended to report.html")


    input("\nPress Enter to return...")


def run():
    print("\n[🕵️ OSINT Toolkit]")
    print("[1] Username Lookup")
    print("[2] Domain OSINT")
    print("[3] Email OSINT")
    print("[4] Back to Main Menu")

    choice = input("Select an option: ").strip()

    if choice == '1':
        username = input("Enter a username: ").strip()
        if username:
            check_username(username)
    elif choice == '2':
        run_domain_osint()
    elif choice == '3':
        run_email_osint()
    else:
        return
