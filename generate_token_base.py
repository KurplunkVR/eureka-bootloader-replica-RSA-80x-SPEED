import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load config
with open("config.json", "r") as f:
    cfg = json.load(f)

SERIAL = cfg["serial"]

# Load public key
pubkey_pem = Path(cfg["public_key"]).read_bytes()
pubkey = serialization.load_pem_public_key(pubkey_pem, backend=default_backend())

# Get key size in bytes
key_size_bytes = pubkey.key_size // 8

# Build payload (4-byte hdr_len + serial + unlock record)
serial_encoded = SERIAL.encode()
hdr = len(serial_encoded).to_bytes(4, "little")
payload = hdr + serial_encoded + b"\x01"

# Create dummy signature of correct size
dummy_signature = b"\x00" * key_size_bytes

# Combine signature + payload
token = dummy_signature + payload
Path("token_base.bin").write_bytes(token)

print("[✔] Unsigned but structurally valid token created as token_base.bin")
