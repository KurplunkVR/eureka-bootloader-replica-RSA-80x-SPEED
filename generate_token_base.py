import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Load serial from config.json
with open("config.json", "r") as f:
    cfg = json.load(f)

SERIAL = cfg["serial"]

# Generate keypair (or load existing one if you have it)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Save keys
private_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

Path("private_key.pem").write_bytes(private_pem)
Path("public_key.pem").write_bytes(public_pem)

# Construct payload (header + serial + record)
hdr = len(SERIAL).to_bytes(4, "little") + SERIAL.encode()
payload = hdr + b"\x01"  # unlock record

# Sign it
signature = key.sign(
    payload,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Build final token
token = signature + payload
Path("token_base.bin").write_bytes(token)

print("[✔] Signed token_base.bin created.")
