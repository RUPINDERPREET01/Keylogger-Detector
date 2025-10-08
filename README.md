git add README.md
git commit -m "docs: update README with setup guide"
git push
# 🔑 Keylogger Detector (Prototype)

A Python-based project that monitors running processes and flags suspicious activity
(simulated keyloggers, unusual file writes, or suspicious process behavior).

## ✨ Features
- ⚡ Real-time process monitoring (using psutil)
- 🔍 Detects suspicious patterns (keywords like "keylog", unusual file writes)
- 📝 Logs alerts to detector_logs/alerts.log
- 🧪 Simulator included to test detection

## 🚀 How to Run

# clone the repo
git clone git@github.com:RUPINDERPREET01/Keylogger-Detector.git
cd Keylogger-Detector

# create virtual environment
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip install -r requirements.txt
