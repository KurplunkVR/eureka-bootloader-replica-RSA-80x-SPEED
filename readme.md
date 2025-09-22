# eureka-bootloader-replica
Eureka bootloader replica for attempting to find an exploit


# Quest Unlock Tool (Verifier + Attacker)

This project emulates the Meta Quest bootloader’s CheckToken() logic
and provides an attacker harness to test bypass strategies.

## Usage

1. Install dependencies:
   pip install cryptography

2. Place your public key into `keys/public.pem`

3. Configure your serial in `config.json`

4. Run verifier directly:
   python verifier.py

5. Run attacker fuzz harness:
   python attacker.py

