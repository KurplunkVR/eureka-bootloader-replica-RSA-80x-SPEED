# Fuzz Attack.py — GUI-first, low-lag multithreaded mutation fuzzer

import os, random, time, threading, queue
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext, messagebox
import verifier
from verifier import CheckToken

# ======= CONFIG =======
BASE_TOKEN_PATH = "token_base.bin"
OUTPUT_DIR = "fuzz_results"
THREAD_COUNT = max(1, (os.cpu_count() or 4) - 1)
MUTATION_COUNT = 50                 # per token (byte XORs)
GUI_REFRESH_MS = 200                # UI tick
LOG_LEVELS_SHOW = {"ERROR","ANOMALY","BYPASS"}  # drop INFO to avoid spam
LOG_MAX_LINES = 1200                # keep last N lines in GUI
LOG_BATCH_GUI = 300                 # max lines to pull into GUI per tick
LOG_MAX_RATE = 400                  # lines/sec forwarded from raw->UI
STATS_FLUSH_EVERY = 64              # worker updates stats every N iters
# ======================

# Shared state
stop_event = threading.Event()
stats = {}                   # wid -> {"count": int, "status": str}
threads = []
mutations_done = 0
mutations_lock = threading.Lock()

# Queues: raw (from verifier) -> filtered UI
raw_log_q: "queue.Queue[tuple[str,str]]" = queue.Queue(maxsize=10000)
ui_log_q:  "queue.Queue[tuple[str,str]]" = queue.Queue(maxsize=10000)
verifier.external_logger = raw_log_q  # hook verifier logs

# Ensure paths & seed
os.makedirs(OUTPUT_DIR, exist_ok=True)
BASE_TOKEN = Path(BASE_TOKEN_PATH).read_bytes()
if not BASE_TOKEN:
    raise ValueError("Base token is empty")


# ---------- Logging pipeline ----------
def log_proxy_thread():
    """Filter & rate-limit logs from verifier to UI queue."""
    allow_all = (LOG_LEVELS_SHOW == {"ALL"})
    last_sec = int(time.time())
    sent_this_sec = 0
    dropped = 0

    while not stop_event.is_set():
        try:
            level, msg = raw_log_q.get(timeout=0.2)
        except queue.Empty:
            # once a second, emit dropped summary
            now = int(time.time())
            if now != last_sec:
                if dropped:
                    try:
                        ui_log_q.put_nowait(("INFO", f"(dropped {dropped} verbose log lines)"))
                    except queue.Full:
                        pass
                    dropped = 0
                sent_this_sec = 0
                last_sec = now
            continue

        # filter
        if not allow_all and level not in LOG_LEVELS_SHOW:
            dropped += 1
            continue

        # rate limit
        now = int(time.time())
        if now != last_sec:
            if dropped:
                try:
                    ui_log_q.put_nowait(("INFO", f"(dropped {dropped} verbose log lines)"))
                except queue.Full:
                    pass
                dropped = 0
            sent_this_sec = 0
            last_sec = now

        if sent_this_sec >= LOG_MAX_RATE:
            dropped += 1
            continue

        try:
            ui_log_q.put_nowait((level, msg))
            sent_this_sec += 1
        except queue.Full:
            dropped += 1


def console_mirror_thread():
    """Optional: mirror significant UI logs to console only."""
    while not stop_event.is_set():
        try:
            level, msg = ui_log_q.get(timeout=0.2)
            # put back for GUI to read too
            try:
                ui_log_q.put_nowait((level, msg))
            except queue.Full:
                pass
            if level in {"ERROR","ANOMALY","BYPASS"}:
                print(f"[{level}] {msg}")
        except queue.Empty:
            continue


# ---------- Mutations ----------
def mutate_token(base: bytes) -> bytes:
    t = bytearray(base)
    # XOR random bytes
    for _ in range(random.randint(1, MUTATION_COUNT)):
        idx = random.randrange(len(t))
        t[idx] ^= random.randint(1, 255)
    # occasional insert/delete for structure perturbation
    r = random.random()
    if r < 0.08 and len(t) > 1:
        del t[random.randrange(len(t))]
    elif r < 0.16:
        t.insert(random.randrange(len(t)+1), random.randrange(256))
    return bytes(t)


# ---------- Worker ----------
def fuzz_worker(wid: int):
    global mutations_done
    count = 0
    stats[wid] = {"count": 0, "status": "START"}

    while not stop_event.is_set():
        mutated = mutate_token(BASE_TOKEN)
        try:
            result = CheckToken(mutated)
        except Exception as e:
            fname = os.path.join(OUTPUT_DIR, f"exception_{wid}_{int(time.time())}.bin")
            Path(fname).write_bytes(mutated)
            stats[wid] = {"count": count, "status": f"EXC {e}"}
            try: ui_log_q.put_nowait(("ERROR", f"Worker {wid} exception: {e} -> {fname}"))
            except queue.Full: pass
            stop_event.set()
            break

        count += 1
        if (count % STATS_FLUSH_EVERY) == 0:
            stats[wid] = {"count": count, "status": "OK"}
        if (count & 0xFF) == 0:
            with mutations_lock:
                mutations_done += 256  # amortize

        if result == 0:
            fname = os.path.join(OUTPUT_DIR, f"bypass_{wid}_{int(time.time())}.bin")
            Path(fname).write_bytes(mutated)
            stats[wid] = {"count": count, "status": "BYPASS!"}
            try: ui_log_q.put_nowait(("BYPASS", f"Worker {wid} FOUND BYPASS -> {fname}"))
            except queue.Full: pass
            stop_event.set()
            break
        elif result != 0x8000000000000015:
            fname = os.path.join(OUTPUT_DIR, f"anomaly_{wid}_{int(time.time())}_{hex(result)}.bin")
            Path(fname).write_bytes(mutated)
            stats[wid] = {"count": count, "status": f"ANOMALY {hex(result)}"}
            try: ui_log_q.put_nowait(("ANOMALY", f"Worker {wid} anomaly {hex(result)} -> {fname}"))
            except queue.Full: pass

    if "status" not in stats.get(wid, {}):
        stats[wid] = {"count": count, "status": "DONE"}


# ---------- GUI ----------
class FuzzGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Quest Bootloader Token Fuzzer — Low-lag")

        # Header
        top = tk.Frame(root); top.pack(fill="x", padx=8, pady=6)
        self.stop_btn = tk.Button(top, text="🛑 Stop", command=self.stop_all, bg="red", fg="white")
        self.stop_btn.pack(side="right")
        self.total_label = tk.Label(top, text="Total Executions: 0", font=("Consolas", 10, "bold"))
        self.total_label.pack(side="left")
        self.rate_label = tk.Label(top, text="Throughput: 0/s")
        self.rate_label.pack(side="left", padx=12)

        # Thread stats
        body = tk.Frame(root); body.pack(fill="both", expand=True, padx=8, pady=4)
        left = tk.Frame(body); left.pack(side="left", anchor="n")
        self.labels = {}
        for i in range(THREAD_COUNT):
            lbl = tk.Label(left, text=f"Thread {i:02d}: START | 0 cases", anchor="w", width=30)
            lbl.pack(anchor="w")
            self.labels[i] = lbl

        # Logs
        right = tk.Frame(body); right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="Logs (filtered)").pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(right, width=100, height=28, state="disabled", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True)

        # Start background after GUI shows
        root.after(0, self.launch_background)

        # UI loop
        self._last_mut = 0
        self._last_t = time.perf_counter()
        root.after(GUI_REFRESH_MS, self.refresh_ui)

    def launch_background(self):
        # proxy (filter+rate-limit) and console mirror
        t1 = threading.Thread(target=log_proxy_thread, daemon=True); t1.start(); threads.append(t1)
        t2 = threading.Thread(target=console_mirror_thread, daemon=True); t2.start(); threads.append(t2)
        # workers
        for wid in range(THREAD_COUNT):
            stats[wid] = {"count": 0, "status": "START"}
            t = threading.Thread(target=fuzz_worker, args=(wid,), daemon=True)
            t.start(); threads.append(t)

    def stop_all(self):
        self.stop_btn.config(state="disabled")
        stop_event.set()

    def _trim_log(self):
        try:
            lines = int(float(self.log_text.index('end-1c').split('.')[0]))
            if lines > LOG_MAX_LINES:
                # remove oldest chunk (keep tail)
                self.log_text.delete('1.0', f'{lines-LOG_MAX_LINES}.0')
        except Exception:
            pass

    def refresh_ui(self):
        # Stats
        total = 0
        for wid in range(THREAD_COUNT):
            st = stats.get(wid, {"count": 0, "status": "-"})
            total += st["count"]
            self.labels[wid].config(text=f"Thread {wid:02d}: {st['status']} | {st['count']} cases")
        self.total_label.config(text=f"Total Executions: {total}")

        # Throughput
        now = time.perf_counter()
        with mutations_lock:
            cur = mutations_done
        dt = max(now - self._last_t, 1e-3)
        rate = int((cur - self._last_mut) / dt)
        self.rate_label.config(text=f"Throughput: {rate}/s")
        self._last_t = now
        self._last_mut = cur

        # Logs (batched)
        pulled = 0
        if ui_log_q.qsize():
            self.log_text.config(state="normal")
            while pulled < LOG_BATCH_GUI:
                try:
                    level, msg = ui_log_q.get_nowait()
                except queue.Empty:
                    break
                ts = datetime.now().strftime("%H:%M:%S")
                self.log_text.insert(tk.END, f"[{ts}] [{level}] {msg}\n")
                pulled += 1
            self._trim_log()
            self.log_text.config(state="disabled")
            self.log_text.see(tk.END)

        if not stop_event.is_set():
            self.root.after(GUI_REFRESH_MS, self.refresh_ui)
        else:
            messagebox.showinfo("Fuzzer", "Fuzzing stopped.")

# ---------- Entrypoint ----------
def main():
    root = tk.Tk()
    gui = FuzzGUI(root)
    print(">>> GUI up — starting workers")
    try:
        root.mainloop()
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)
        print("Fuzz complete. Results in", OUTPUT_DIR)

if __name__ == "__main__":
    main()
