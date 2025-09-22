import os
import time
import threading
import queue
import logging
from datetime import datetime
from verifier import CheckToken, SERIAL
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# --------------------------------------------------------------------
# Config
# --------------------------------------------------------------------
OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

THREAD_COUNT = 8  # Adjust as needed

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

# --------------------------------------------------------------------
# Worker Thread
# --------------------------------------------------------------------
def worker(wid, stop_event, result_queue, stats):
    attempts = 0
    while not stop_event.is_set():
        try:
            attempts += 1
            key, priv, pub = generate_keypair()
            token = build_token(key)
            result = CheckToken(token)

            if result == 0:
                ts = int(time.time())
                result_queue.put((ts, priv, pub, token, wid))
                stop_event.set()
                break
            else:
                stats[wid] = {"attempts": attempts, "status": "FAIL"}
        except Exception as e:
            stats[wid] = {"attempts": attempts, "status": f"ERROR: {e}"}
            stop_event.set()
            break
    stats[wid] = {"attempts": attempts, "status": "STOPPED"}

# --------------------------------------------------------------------
# Monitor Thread
# --------------------------------------------------------------------
def monitor(stats, stop_event, start_ts):
    try:
        while not stop_event.is_set():
            os.system("cls" if os.name == "nt" else "clear")
            elapsed = time.time() - start_ts
            print(f"=== Multi-Threaded Token Tester ===  (uptime: {elapsed:.1f}s)")
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            print("-" * 60)

            total_attempts = 0
            for wid in sorted(stats.keys()):
                s = stats[wid]
                total_attempts += s.get("attempts", 0)
                print(f"Thread {wid:02d}: attempts={s.get('attempts', 0)} status={s.get('status', '-')}")
            print("-" * 60)
            print(f"Total Attempts: {total_attempts}")
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()

# --------------------------------------------------------------------
# Main Execution
# --------------------------------------------------------------------
def main():
    stats = {}
    stop_event = threading.Event()
    result_queue = queue.Queue()
    threads = []
    start_ts = time.time()

    # Start monitor
    monitor_thread = threading.Thread(target=monitor, args=(stats, stop_event, start_ts))
    monitor_thread.start()

    # Launch workers
    for wid in range(THREAD_COUNT):
        stats[wid] = {"attempts": 0, "status": "STARTED"}
        t = threading.Thread(target=worker, args=(wid, stop_event, result_queue, stats))
        t.start()
        threads.append(t)

    # Wait for completion
    for t in threads:
        t.join()

    stop_event.set()
    monitor_thread.join()

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
    logging.basicConfig(level=logging.ERROR)  # Reduce noise
    main()
