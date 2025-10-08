# detector.py
"""
Keylogger-Detector (prototype)
Heuristic-based detector that monitors processes and raises alerts for suspicious behavior.
SAFE: This does NOT include keylogger creation code. It's a monitoring/demo tool only.
"""

import time
import psutil
import hashlib
import os
from datetime import datetime
from collections import defaultdict

try:
    from rich import print
except Exception:
    # fallback if rich not installed
    def print(*args, **kwargs):
        _builtins_['print'](*args, **kwargs)

# ------------------------
# Config / thresholds
# ------------------------
CHECK_INTERVAL = 3.0  # seconds between checks
SUSPICIOUS_NAMES = {
    "keylogger", "klg", "spy", "logger", "keylog", "key_log", "winlogon.exe.fake"
}
SUSPICIOUS_DIRS = [
    "temp", "downloads", "appdata", "local\\temp", "/tmp",
    "/home/kali/temp_key_sim"   # <-- simulator writes here
]
SUSPICIOUS_FILE_TOKEN = {"keylog", "input_log", "keys", "typed"}
ALERT_THRESHOLD = 3  # score threshold to raise alert

LOG_DIR = "detector_logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

# ------------------------
# Helpers
# ------------------------
def hash_path(path):
    try:
        return hashlib.sha256(path.encode()).hexdigest()[:8]
    except Exception:
        return "err"

def note_alert(data):
    ts = datetime.utcnow().isoformat()
    entry = f"{ts} | {data}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry)
    except Exception:
        pass
    print(f"[bold red]ALERT[/] {entry.strip()}")

def process_baseline():
    """Return dict pid -> (name, exe, create_time) as baseline snapshot"""
    snap = {}
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "create_time"]):
        info = p.info
        snap[info["pid"]] = {
            "name": (info.get("name") or "").lower(),
            "exe": (info.get("exe") or ""),
            "create_time": info.get("create_time") or 0
        }
    return snap

def suspicious_score_for_proc(pid, info):
    """
    Compute a heuristic score for the process based on name, path, network activity, file handles.
    Higher score = more suspicious. This is for demo purposes only.
    """
    score = 0
    name = info.get("name", "").lower()
    exe = info.get("exe", "") or ""
    exe_low = exe.lower()

    # name-based heuristics
    for token in SUSPICIOUS_NAMES:
        if token in name or token in exe_low:
            score += 2

    # directory heuristic
    for s in SUSPICIOUS_DIRS:
        if s in exe_low:
            score += 1

    # network connections heuristic
    try:
        p = psutil.Process(pid)
        conns = p.connections(kind='inet')
        if conns:
            score += 1
    except Exception:
        pass

    # open files / descriptors heuristic
    try:
        p = psutil.Process(pid)
        # num_fds available on Unix, use platform-appropriate attributes
        if hasattr(p, "num_fds"):
            num_fds = p.num_fds()
            if num_fds and num_fds > 50:
                score += 1
        elif hasattr(p, "num_handles"):
            # Windows fallback
            num_handles = p.num_handles()
            if num_handles and num_handles > 200:
                score += 1
    except Exception:
        pass
# file name token heuristic (best effort)
    try:
        p = psutil.Process(pid)
        for of in p.open_files():
            low = (of.path or "").lower()
            # boost if file path contains suspicious tokens or simulator dir
            if "/home/kali/temp_key_sim" in low:
                score += 2
            for tok in SUSPICIOUS_FILE_TOKENS:
                if tok in low:
                    score += 2
                    break
    except Exception:
        pass
    return score

# ------------------------
# Main monitor loop
# ------------------------
def monitor_loop():
    print("[cyan]Starting Keylogger Detector baseline snapshot...[/]")
    baseline = process_baseline()
    seen = set(baseline.keys())
    scores = defaultdict(int)
    last_checked = time.time()

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
            current = {}
            for p in psutil.process_iter(attrs=["pid", "name", "exe", "create_time"]):
                info = p.info
                pid = info["pid"]
                current[pid] = {
                    "name": (info.get("name") or "").lower(),
                    "exe": (info.get("exe") or ""),
                    "create_time": info.get("create_time") or 0
                }

                # New process detection (informational)
                if pid not in seen:
                    seen.add(pid)
                    msg = f"New process pid={pid}, name={info.get('name')} exe={info.get('exe')}"
                    print("[yellow]New process detected:[/]", msg)
                    note_alert(msg)

                # Compute heuristics
                proc_score = suspicious_score_for_proc(pid, current[pid])
                if proc_score:
                    # accumulate or take max depending on your preference
                    scores[pid] = max(scores[pid], proc_score)
                    if scores[pid] >= ALERT_THRESHOLD:
                        msg = (f"Suspicious process pid={pid} "
                               f"name={current[pid]['name']} exe={current[pid]['exe']} score={scores[pid]}")
                        note_alert(msg)

            # cleanup: remove terminated pids from scores
            for pid in list(scores.keys()):
                if pid not in current:
                    del scores[pid]

            # periodic status update
            if time.time() - last_checked > 60:
                print(f"[green]Status[/]: monitored {len(current)} processes; alerts logged to {LOG_FILE}")
                last_checked = time.time()

    except KeyboardInterrupt:
        print("[bold]Stopping detector...[/]")

if __name__ == "__main__":
    monitor_loop()
