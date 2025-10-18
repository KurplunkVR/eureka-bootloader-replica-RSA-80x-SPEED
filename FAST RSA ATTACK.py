#!/usr/bin/env python3
# --------------------------------------------------------------------
# MADE BY KurplunkVR
# --------------------------------------------------------------------
import os
import time
import threading
import queue
import logging
from datetime import datetime
from verifier import CheckToken, SERIAL
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from multiprocessing import Process, Queue, Event, cpu_count
import math
from queue import Empty

# multiprocessing queue for PEM tuples
key_queue = Queue(maxsize=1024)

# use multiprocessing Event so processes see it
mp_stop_event = Event()

rr_lock = threading.Lock()
next_thread = 0  # shared across threads

# --------------------------------------------------------------------
# Config
# --------------------------------------------------------------------
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

THREAD_COUNT = max(1, cpu_count() - 2)

# --------------------------------------------------------------------
# RSA / Token Generation
# --------------------------------------------------------------------
def generate_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, private_pem, public_pem

def build_token(key):
    hdr = len(SERIAL).to_bytes(4, "little") + SERIAL.encode()
    payload = hdr + b"\x01"
    signature = key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature + payload

# key generator process
def keygen_worker(stop_event, key_queue, batch_size=8, key_size=2048):
    while not stop_event.is_set():
        batch = []
        for _ in range(batch_size):
            key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            priv = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            token = build_token(key)
            batch.append((token, priv, pub))
        for item in batch:
            try:
                key_queue.put(item, timeout=1)
            except Exception:
                if stop_event.is_set():
                    return

# --------------------------------------------------------------------
# Worker Thread
# --------------------------------------------------------------------
stats_lock = threading.Lock()

# easy replacement!!!
def call_check(token: bytes) -> int:
    return CheckToken(token)

BATCH_PER_TURN = 256  # keys grabbed per round

def worker(wid, stop_event, result_queue, stats, key_queue):
    global next_thread
    attempts = 0

    while not stop_event.is_set():
        keys_to_process = []

        # acquire lock once per batch
        with rr_lock:
            if wid != next_thread:
                continue  # not this thread's turn

            # determine how many keys we can grab right now
            try:
                qsize = key_queue.qsize()
            except Exception:
                qsize = 0
            grab_count = min(BATCH_PER_TURN, qsize)

            for _ in range(grab_count):
                try:
                    keys_to_process.append(key_queue.get_nowait())
                except Empty:
                    break

            # advance the round-robin pointer
            next_thread = (next_thread + 1) % THREAD_COUNT

        # process keys outside the lock
        for token, priv_pem, pub_pem in keys_to_process:
            attempts += 1
            # nuh uh its too slow to load it lol
            # key = load_pem_private_key(priv_pem, password=None)
            # token = build_token(key)
            result = call_check(token)

            if result == 0:
                ts = int(time.time())
                result_queue.put((ts, priv_pem, pub_pem, token, wid))
                stop_event.set()
                break

            # update stats
            with stats_lock:
                stats[wid] = {"attempts": attempts, "status": "FAIL"}

        # tiny sleep to prevent busy-loop if queue is empty
        time.sleep(0.005)

# --------------------------------------------------------------------
# Monitor Thread
# --------------------------------------------------------------------
def monitor(stats, stop_event, start_ts):
    try:
        while not stop_event.is_set():
            print("\033[H\033[J", end="")  # clear for linux
            elapsed = time.time() - start_ts
            print(f"=== Multi-Threaded Token Tester ===  (uptime: {elapsed:.1f}s)")
            print(f"=== Improved by KurplunkVR ===")
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            print("-" * 60)
            total_attempts = 0
            with stats_lock:
                for wid in sorted(stats.keys()):
                    s = stats[wid]
                    total_attempts += s.get("attempts", 0)
                    print(f"Thread {wid:02d}: attempts={s.get('attempts', 0)} status={s.get('status', '-')}")
            print("-" * 60)
            try:
                qsize = key_queue.qsize()
            except Exception:
                qsize = -1
            print(f"Total Attempts: {total_attempts}   KeyQueueSize: {qsize}")
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        mp_stop_event.set()

# --------------------------------------------------------------------
# Main Execution
# --------------------------------------------------------------------
def main():
    stats = {}
    # use multiprocessing Event for producers; worker threads read same event
    stop_event = mp_stop_event
    # plain queue for results (threads use it)
    result_queue = queue.Queue()
    threads = []
    start_ts = time.time()

    monitor_thread = threading.Thread(target=monitor, args=(stats, stop_event, start_ts), daemon=True)
    monitor_thread.start()

    # start key generators (processes)
    gens = []
    for _ in range(max(1, cpu_count() - 2)):
        p = Process(target=keygen_worker, args=(stop_event, key_queue, 4, 2048))
        p.daemon = True
        p.start(); gens.append(p)

    # Launch workers (threads)
    for wid in range(THREAD_COUNT):
        with stats_lock:
            stats[wid] = {"attempts": 0, "status": "STARTED"}
        t = threading.Thread(target=worker, args=(wid, stop_event, result_queue, stats, key_queue), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        # cleanup producers
        for p in gens:
            if p.is_alive():
                p.terminate()
                p.join(timeout=1)

        monitor_thread.join(timeout=1)

    if not result_queue.empty():
        ts, priv, pub, token, wid = result_queue.get()
        with open(os.path.join(OUTPUT_DIR, f"private_{ts}.pem"), "wb") as f:
            f.write(priv)
        with open(os.path.join(OUTPUT_DIR, f"public_{ts}.pem"), "wb") as f:
            f.write(pub)
        with open(os.path.join(OUTPUT_DIR, f"token_{ts}.bin"), "wb") as f:
            f.write(token)
        print(f"\n[✔] SUCCESS! Verified by thread {wid:02d} @ {ts}")
    else:
        print("\n[✘] No valid token found.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    main()
