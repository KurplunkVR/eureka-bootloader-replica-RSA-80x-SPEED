from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
import math

# Load any RSA public key PEM
pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9sO6BRWaFKshZyvJb7XH
D/IqRnoq0JlIp7Z1tuJ9n015LnsXfab2wL2QZubVU2gRc4D3qOG9AyyFG7ykr6zo
5YpfYQyNRPMi6pMyJoX7QQMnEUPx9uQlTV5i8DtZ9Iyx5V2ftYDRrTXBHa6NHh1E
eaMgdtXX6848SL0HhJClaEtLx+YBLMKZxz/QvEhgzwjahP9gdG08XUc8yuSFkpre
jWyJrHBwgS5DNtmofe9i4m+dbpKXxKvb9MDuKGIL2r90trcyzUzfYb7oetBSPhWM
8VpR+D7TgCmjy9XoDdIWsikAmC5RlT79jcGi//N/C+dY7fOF5F864IZJCN8qE18E
YwIDAQAB
-----END PUBLIC KEY-----"""

key = RSA.import_key(pem)
n = key.n
e = key.e

print("Public modulus N (bits):", n.bit_length())
print("Public exponent e:", e)

# Brute-force factorization attempt (toy only!)
print("\nAttempting to factor N...")
for guess in range(2, int(math.isqrt(n)) + 1):
    if n % guess == 0:
        p = guess
        q = n // guess
        print("Found factors:", p, q)
        phi = (p-1)*(q-1)
        d = inverse(e, phi)
        print("Private exponent d:", d)
        break
else:
    print("No factors found (expected for large RSA like 2048-bit).")
