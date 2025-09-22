# Filename: fuzz_main.py
import threading
import os, random, time, hashlib, struct
import queue
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext, messagebox

import verifier
from verifier import CheckToken, gEfiMiscPartitionGuid


# ======= CONFIG =======
BASE_TOKEN_PATH = "token_base.bin"
DEFAULT_THREAD_COUNT = 5
GUI_REFRESH_MS = 100
LOG_MAX_LINES = 500
LOG_BATCH_GUI = 50
# ======================

log_queue = queue.Queue(maxsize=10000)
stats_lock = threading.Lock()
stats = {}
mutations_done = 0
stop_event = threading.Event()
seen_hashes = set()

verifier.external_logger = log_queue
BASE_TOKEN = Path(BASE_TOKEN_PATH).read_bytes()
if not BASE_TOKEN:
    raise ValueError("Base token is empty")

def build_token(serial: bytes, records: list, sig_size=256):
    payload = bytearray()
    payload += struct.pack("<I", len(serial))
    payload += serial
    payload += gEfiMiscPartitionGuid

    for rec in records:
        rec_type, data = rec
        payload.append(rec_type)
        payload += data

    fake_sig = os.urandom(sig_size)  # garbage, assume glitch bypass
    return fake_sig + payload

def mutate_structured(serial: bytes, records: list):
    choice = random.choice([
        "hdrlen_offby1", "serial_null", "guid_flip",
        "add_unlock", "add_rollback"
    ])

    if choice == "hdrlen_offby1":
        serial = serial + b"A"
    elif choice == "serial_null":
        serial = serial[:len(serial)//2] + b"\x00" + serial[len(serial)//2:]
    elif choice == "guid_flip":
        records.insert(0, (0xFF, os.urandom(4)))
    elif choice == "add_unlock":
        records.append((2, b"\x01"))  # unlock=1
    elif choice == "add_rollback":
        records.append((3, b"\x00"))

    return build_token(serial, records)



def mutate_token(base_serial: bytes, sig_size=256):
    records = []
    return mutate_structured(base_serial, records)


# ---------- Worker ----------
def worker_thread(wid: int):
    global mutations_done
    stats[wid] = {"count": 0, "status": "START"}

    while not stop_event.is_set():
        tok = mutate_token(BASE_TOKEN)
        digest = hashlib.sha256(tok).digest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)

        try:
            result = CheckToken(tok)
        except Exception as e:
            log_queue.put(("ERROR", f"Worker {wid} EXC {repr(e)}"))
            with stats_lock:
                stats[wid]["status"] = "EXC"
            stop_event.set()
            break

        with stats_lock:
            stats[wid]["count"] += 1
            stats[wid]["status"] = "OK"
        mutations_done += 1

        if result == 0:
            log_queue.put(("BYPASS", f"Worker {wid} BYPASS"))
            with stats_lock:
                stats[wid]["status"] = "BYPASS"
            stop_event.set()
            break
        elif result != 0x8000000000000015:
            log_queue.put(("ANOMALY", f"Worker {wid} anomaly {hex(result)}"))

# ---------- GUI ----------
class FuzzGUI:
    def __init__(self, root):
        self.root = root
        self.thread_count = DEFAULT_THREAD_COUNT
        self.worker_threads = []
        root.title("Quest Token Bootloader Fuzz Attack Emulator")

        # Controls
        top = tk.Frame(root)
        top.pack(fill="x", padx=8, pady=6)
        tk.Label(top, text="Threads:").pack(side="left")
        self.thread_count_var = tk.IntVar(value=DEFAULT_THREAD_COUNT)
        self.thread_spin = tk.Spinbox(top, from_=1, to=50, width=5, textvariable=self.thread_count_var)
        self.thread_spin.pack(side="left", padx=5)

        self.start_btn = tk.Button(top, text="▶ Start", command=self.start)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = tk.Button(top, text="🛑 Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        # Log level filter checkboxes
        self.filter_levels = {
            "INFO": tk.BooleanVar(value=True),
            "DEBUG": tk.BooleanVar(value=True),
            "ERROR": tk.BooleanVar(value=True),
            "BYPASS": tk.BooleanVar(value=True),
            "ANOMALY": tk.BooleanVar(value=True),
        }

        filter_frame = tk.Frame(root)
        filter_frame.pack(anchor="w", padx=8)
        tk.Label(filter_frame, text="Show Logs:").pack(side="left")
        for lvl, var in self.filter_levels.items():
            cb = tk.Checkbutton(filter_frame, text=lvl, variable=var)
            cb.pack(side="left", padx=(0, 5))

        # Toggle checkbox for hiding VerifyFinal / Signature errors
        self.hide_verify_errors_var = tk.BooleanVar(value=True)
        hide_cb = tk.Checkbutton(root, text="Hide VerifyFinal / InvalidSignature Logs", variable=self.hide_verify_errors_var)
        hide_cb.pack(anchor="w", padx=8, pady=(0,5))

        self.total_label = tk.Label(root, text="Total Executions: 0")
        self.total_label.pack(anchor="w", padx=8)
        self.rate_label = tk.Label(root, text="Throughput: 0/s")
        self.rate_label.pack(anchor="w", padx=8)

        self.thread_frame = tk.Frame(root)
        self.thread_frame.pack(side="left", anchor="n", padx=8, pady=4)
        self.labels = {}

        self.log_text = scrolledtext.ScrolledText(root, width=80, height=25, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=4)

        self._last_t = time.perf_counter()
        self._last_mut_done = mutations_done
        self.root.after(GUI_REFRESH_MS, self.refresh_ui)

    def start(self):
        global mutations_done
        mutations_done = 0
        self.thread_count = self.thread_count_var.get()
        stop_event.clear()
        self.clear_labels()

        with stats_lock:
            stats.clear()
            for i in range(self.thread_count):
                stats[i] = {"count": 0, "status": "START"}

        self.worker_threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=worker_thread, args=(i,), daemon=True)
            t.start()
            self.worker_threads.append(t)

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def clear_labels(self):
        for lbl in self.labels.values():
            lbl.destroy()
        self.labels.clear()
        for i in range(self.thread_count):
            lbl = tk.Label(self.thread_frame, text=f"Thread {i:02d}: --- | 0", anchor="w", width=30)
            lbl.pack(anchor="w")
            self.labels[i] = lbl

    def stop(self):
        stop_event.set()
        self.stop_btn.config(state="disabled")
        self.start_btn.config(state="normal")

    def _trim_log(self):
        try:
            lines = int(self.log_text.index('end-1c').split('.')[0])
            if lines > LOG_MAX_LINES:
                self.log_text.delete('1.0', f'{lines-LOG_MAX_LINES}.0')
        except Exception:
            pass

    def refresh_ui(self):
        total = 0
        with stats_lock:
            for wid, data in stats.items():
                total += data["count"]
                if wid in self.labels:
                    self.labels[wid].config(text=f"Thread {wid:02d}: {data['status']} | {data['count']}")

        self.total_label.config(text=f"Total Executions: {total}")

        now = time.perf_counter()
        dt = now - self._last_t if now > self._last_t else 1e-3
        rate = int((mutations_done - self._last_mut_done) / dt)
        self.rate_label.config(text=f"Throughput: {rate}/s")
        self._last_t = now
        self._last_mut_done = mutations_done

        entries = []
        try:
            for _ in range(LOG_BATCH_GUI):
                level, msg = log_queue.get_nowait()

                if self.hide_verify_errors_var.get():
                    if "Failed on VerifyFinal" in msg or "Invalid Signature" in msg:
                        continue

                if self.filter_levels.get(level, tk.BooleanVar(value=False)).get():
                    ts = datetime.now().strftime("%H:%M:%S")
                    entries.append(f"[{ts}] [{level}] {msg}")
        except queue.Empty:
            pass

        if entries:
            self.log_text.config(state="normal")
            self.log_text.insert(tk.END, "\n".join(entries) + "\n")
            self._trim_log()
            self.log_text.see(tk.END)
            self.log_text.config(state="disabled")

        if not stop_event.is_set():
            self.root.after(GUI_REFRESH_MS, self.refresh_ui)
        else:
            messagebox.showinfo("Stopped", "Fuzzing stopped.")

# ---------- Main ----------
def main():
    root = tk.Tk()
    gui = FuzzGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
