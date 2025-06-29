from Crypto.Cipher import AES
import base64
import hashlib

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt_data(raw, secret_key):
    private_key = hashlib.sha256(secret_key.encode("utf-8")).digest()
    raw = pad(raw)
    cipher = AES.new(private_key, AES.MODE_ECB)
    encrypted = base64.b64encode(cipher.encrypt(raw.encode("utf-8")))
    return encrypted.decode('utf-8')

def decrypt_data(enc, secret_key):
    private_key = hashlib.sha256(secret_key.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    cipher = AES.new(private_key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(enc).decode("utf-8"))
    return decrypted
