# PhishGuard Enterprise: Zero-Day Threat Intelligence Engine 🛡️

An advanced, AI-driven Security Operations Center (SOC) dashboard for detecting and analyzing zero-day phishing threats using Lexical Analysis, Shannon Entropy, and Threat Intelligence mapping.

## 🔥 Key Features
* **Live Forensics Terminal:** Real-time data extraction and logging.
* **Lexical Pattern Recognition:** URL heuristic scanning & IP obfuscation detection.
* **Threat Intelligence Sync:** Simulated global VirusTotal engine mapping & WHOIS Domain Age tracking.
* **Automated Audit Reports:** One-click PDF generation for SOC compliance.
* **Local Threat Database:** SQLite-backed historical intelligence logging.

## 💻 Tech Stack
* **Frontend:** HTML5, Tailwind CSS, JavaScript, html2pdf.js
* **Backend:** Python, FastAPI, Uvicorn
* **Database:** SQLite

## 🚀 How to Run Locally
1. Start the Backend Engine:
   `python main.py`
2. Start the Frontend Server:
   `python -m http.server 8081`
3. Open `http://localhost:8081` in your browser.
