# SecurityScanKit v2.0 - CISO Security Scanner
# Windows Installation Guide
# ===========================================

## Quick Start
1. Unzip SecurityScanKit_v2.zip
2. Double-click  start.bat
3. Open browser: http://localhost:3000

## Requirements
- Python 3.10+   https://www.python.org/downloads/
- Node.js 18+    https://nodejs.org/

## Manual Start
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev

## URLs
- Dashboard : http://localhost:3000
- API Docs  : http://localhost:8000/docs

## Project Structure
SecurityScanKit_v2/
  start.bat                    <- Double-click to run
  stop.bat                     <- Stop all servers
  scan_targets_template.xlsx   <- Server registration form
  backend/
    main.py                    <- FastAPI server (port 8000)
    ai_analyzer.py             <- Claude AI analysis
    requirements.txt
    scanner/
      port_scanner.py          <- nmap + socket scan
      web_scanner.py           <- OWASP, headers, paths
      ssl_scanner.py           <- TLS, cert, cipher
      db_scanner.py            <- DB exposure check
      network_scanner.py       <- SNMP, Telnet, creds
    reporter/
      pdf_report.py            <- PDF report generator
      excel_report.py          <- Excel report generator
  frontend/
    src/App.jsx                <- Enterprise dashboard UI
