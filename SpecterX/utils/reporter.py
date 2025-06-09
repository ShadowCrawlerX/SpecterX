# utils/reporter.py

import os
from datetime import datetime

REPORT_HTML = "output/report.html"

def init_html_report():
    os.makedirs("output", exist_ok=True)
    if not os.path.exists(REPORT_HTML):
        with open(REPORT_HTML, "w", encoding="utf-8") as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SpecterX Recon Report</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; padding: 20px; }
    h1, h2 { color: #0ff; }
    .block { border-top: 1px solid #444; margin-top: 20px; padding-top: 10px; }
    .timestamp { color: #888; font-size: 0.9em; }
    .section-title { color: #ff0; margin-bottom: 5px; }
    pre { background: #222; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .filters { margin: 20px 0; }
    .filters button {
      background: #222; color: #0ff; border: 1px solid #0ff;
      padding: 5px 10px; margin-right: 10px; cursor: pointer;
    }
    .filters button.active { background: #0ff; color: #000; }
    .hidden { display: none; }
    .live-dot {
      width: 10px; height: 10px; background: lime; border-radius: 50%;
      display: inline-block; margin-left: 10px; animation: blink 1s infinite;
    }
    @keyframes blink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.2; }
    }
  </style>
</head>
<body>
  <h1>SpecterX Recon Report <span class="live-dot"></span></h1>

  <div class="filters">
    <button onclick="showAll()" class="active">Show All</button>
    <button onclick="filter('Subdomain Scanner')">Subdomain Scanner</button>
    <button onclick="filter('Port Scanner')">Port Scanner</button>
    <button onclick="filter('LAN IP Scanner')">LAN IP Scanner</button>
    <button onclick="filter('Web Fingerprinter')">Web Fingerprinter</button>
    <button onclick="filter('Username OSINT')">Username OSINT</button>
    <button onclick="filter('Email OSINT')">Email OSINT</button>
    <button onclick="filter('Exploit Matcher')">Exploit Matcher</button>
    <button onclick="filter('Brute-Force Results')">Brute-Force</button>
  </div>

  <script>
    function filter(module) {
      document.querySelectorAll('.block').forEach(b => {
        if (b.dataset.module === module) {
          b.classList.remove('hidden');
        } else {
          b.classList.add('hidden');
        }
      });
      document.querySelectorAll('.filters button').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
    }

    function showAll() {
      document.querySelectorAll('.block').forEach(b => b.classList.remove('hidden'));
      document.querySelectorAll('.filters button').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
    }

    // 🔄 Smart Auto-Reload based on timestamp
    let lastUpdate = null;
    async function checkUpdate() {
      try {
        const res = await fetch("report.html", { cache: "no-store" });
        const text = await res.text();
        const match = text.match(/<div class="timestamp">(.+?)<\\/div>/g);
        if (match) {
          const latest = match[match.length - 1];
          if (latest !== lastUpdate) {
            lastUpdate = latest;
            location.reload();
          }
        }
      } catch (err) {
        console.warn("Live update check failed:", err);
      }
    }
    setInterval(checkUpdate, 1000); // check every 5 seconds
  </script>
""")



def write_html_section(module_name, content_lines):
    init_html_report()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    normalized_name = module_name.title()
    block = f"""
<div class="block" data-module="{normalized_name}">
  <h2 class="section-title">{normalized_name}</h2>
  <div class="timestamp">{timestamp}</div>
  <pre>{chr(10).join(content_lines)}</pre>
</div>
"""


    with open(REPORT_HTML, "a", encoding="utf-8") as f:
        f.write(block)
