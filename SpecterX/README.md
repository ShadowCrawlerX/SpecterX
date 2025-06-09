# 🕵️‍♀⃣ SpecterX - Red Team Reconnaissance Framework

**Version:** 1.0
**Author:** Mr Robot
**License:** MIT
**Platform:** Windows / Linux
**Language:** Python 3.9+

---

SpecterX is a powerful, modular red team and OSINT (Open Source Intelligence) automation toolkit written in Python. It unifies essential reconnaissance, enumeration, brute-force, and intelligence-gathering tasks into an interactive terminal-driven environment with live auto-updating HTML reporting.

Designed for ethical hackers, bug bounty hunters, students, and cybersecurity analysts, SpecterX is clean, fast, and extensible.

---

## 🔍 Core Features

* ✨ Interactive CLI interface with clearly organized tool categories
* 🔎 Recon modules: Subdomain, Ports, Web Fingerprint, LAN
* 🤖 OSINT modules: Usernames, Domains, Emails
* 🔐 Brute-Force: FTP and SSH
* 📊 Live HTML reporting with auto-refresh and module filtering
* 🔄 Modular architecture, easy to expand

---

## 🔹 Modules Overview

### 🔧 Technical Recon

* **Subdomain Scanner**
  DNS brute-force using a wordlist

* **Port Scanner + Exploit Matcher**
  Threaded TCP scan with banner grabbing + CVE lookup via exploits.json

* **Web Fingerprinter**
  Title, CMS, server headers, X-Powered-By

* **LAN IP Scanner**
  Full network device discovery via ARP and ping sweep

### 🕵️ OSINT

* **Username Scanner**
  Detect accounts on GitHub, Reddit, Twitter, Telegram, etc.

* **Domain OSINT**
  WHOIS and full DNS records (A, MX, TXT, NS)

* **Email OSINT**
  Gravatar check + MX records

### 🔐 Brute-Force Tools

* **FTP Brute-Force** using `ftplib`
* **SSH Brute-Force** using `paramiko`
* Username/password wordlist support

---

## 📅 Live HTML Reporting

All module outputs are written to `output/report.html`:

* Timestamped sections with headings and preformatted results
* Filter buttons (Port Scanner, OSINT, etc.)
* Live auto-refresh every few seconds
* Easy to review across sessions or export

---

## 🛠️ Setup Instructions

### Requirements:

* Python 3.9+

```bash
pip install -r requirements.txt
```

### Recommended Libraries:

* requests
* paramiko
* dnspython
* whois
* netifaces

---

## 🚀 Running SpecterX

```bash
python main.py
```

All results are saved and appended to:

```bash
output/report.html
```

Open that file in a browser for real-time updates.

---

## 📄 Project Structure

```
specterX/
├── core/
│   ├── scanner.py
│   ├── osint.py
│   └── brute.py
├── utils/
│   └── reporter.py
├── data/
│   └── exploits.json
├── wordlists/
│   ├── users.txt
│   └── passwords.txt
│   └── subdomains.txt
├── output/
│   └── report.html
├── main.py
└── README.md
```

---

## 🚀 Upcoming Features (v1.1+)

* Shodan integration
* Favicon hashing + tech detection
* Custom payload generator
* Form brute-forcers (HTTP/SMTP)
* Simple RAT module with file ops (for labs)
* Plugin-based extensions + API key support

---

## 🚀 Development Roadmap (Completed for v1.0)

1. CLI interface and modular tool routing
2. Core recon tools (subdomain, port scan, LAN scan)
3. OSINT tools (usernames, domain, email)
4. Exploit banner matcher with CVEs
5. Brute-force systems (FTP/SSH)
6. Live HTML report system with filters and refresh

---

## 💪 Philosophy

* ✅ Realistic tools for real red team workflows
* ✅ 100% terminal-based, but export-friendly
* ✅ Ethical by design — for lab and authorized usage
* ✅ Built to teach, learn, and impress

---

## 💼 License

MIT — free to use, modify, and contribute. Just don't be a skiddie.

---

## 🧙 About Mr Robot

A student of hacking, automation, and Python — building tools that are practical, powerful, and personal. SpecterX is the culmination of hands-on effort, research, and passion.

> Version 1.0 — “The Eyes of the Hunter”
