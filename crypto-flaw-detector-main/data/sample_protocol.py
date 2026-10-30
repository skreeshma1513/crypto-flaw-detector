"""INTENTIONALLY VULNERABLE DEMO CODE - for static analysis only. Never run this file."""
import hashlib, random, secrets, ssl, requests
from Crypto.Cipher import AES, DES
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SECRET_KEY = "hunter2-super-secret"          # UNSAFE: hardcoded secret
IV = b"1234567890123456"                      # UNSAFE: hardcoded IV

def unsafe_examples(password, data):
    a = hashlib.md5(data).hexdigest()                  # UNSAFE: MD5
    b = hashlib.sha1(data).hexdigest()                 # UNSAFE: SHA-1
    h = hashlib.sha256(password.encode()).hexdigest()  # UNSAFE: fast hash for password
    token = random.randint(0, 999999)                  # UNSAFE: predictable random
    cipher = AES.new(b"0123456789abcdef", AES.MODE_ECB)  # UNSAFE: ECB
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # UNSAFE: short key
    requests.get("https://example.com", verify=False)  # UNSAFE: TLS verification off
    ctx = ssl._create_unverified_context()             # UNSAFE
    return a, b, h, token, cipher, key, ctx

def safe_examples(plaintext):
    key = AESGCM.generate_key(bit_length=256)          # SAFE: AES-GCM
    nonce = secrets.token_bytes(12)                    # SAFE: secrets module
    return AESGCM(key).encrypt(nonce, plaintext, None)
