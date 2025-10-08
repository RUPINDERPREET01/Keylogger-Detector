# Keylogger-Detector (Prototype)

## Objective
Lightweight heuristic-based detector to demonstrate detecting suspicious processes and file-writing behaviour associated with keyloggers.

## Components
- detector.py — main monitoring/detection script
- simulator_writer.py — safe simulator to test detection (writes dummy logs)
- NOTES.md — heuristics and tuning
- detector_logs/alerts.log — generated runtime alerts

## How to run
1. Create and activate venv:
   - python3 -m venv venv
   - source venv/bin/activate (Linux/macOS)  
   - venv\Scripts\Activate.ps1 (Windows PowerShell)

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
