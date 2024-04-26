import hashlib
import hmac
import Crypto.Cipher.AES as AES
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import PKCS1_OAEP
import Crypto.Random as Random
import base64
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def derive_keys(master_secret):
    # Derive the encryption key
    encryption_key = hmac.new(master_secret.encode(), b"encryption", hashlib.sha256).hexdigest()
    # Derive the MAC key
    mac_key = hmac.new(master_secret.encode(), b"mac", hashlib.sha256).hexdigest()
    # Convert hex strings to bytes
    encryption_key_bytes = bytes.fromhex(encryption_key)
    mac_key_bytes = bytes.fromhex(mac_key)
    
    return encryption_key_bytes, mac_key_bytes

def aes_encrypt(data, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(data)

def aes_decrypt(data, key):
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(data[AES.block_size:])

def generate_hmac(data, key_bytes):
    # Directly use key_bytes, assuming it's already in the correct format (bytes)
    return hmac.new(key_bytes, data, hashlib.sha256).digest()

def verify_hmac(data, key_bytes, mac):
    generated_mac = generate_hmac(data, key_bytes)
    return hmac.compare_digest(generated_mac, mac)

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_audit_log_entry(public_key, log_entry):
    """
    Encrypts an audit log entry using RSA encryption.

    Args:
    - public_key (str): The public key in PEM format used for encryption.
    - log_entry (str): The audit log entry to encrypt.

    Returns:
    - str: The encrypted log entry, base64 encoded.
    """
    # Load the public key
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    # Encrypt the log entry
    encrypted_data = cipher.encrypt(log_entry.encode())

    # Return the encrypted data base64 encoded to ensure it's safely written to a text file
    return base64.b64encode(encrypted_data).decode()