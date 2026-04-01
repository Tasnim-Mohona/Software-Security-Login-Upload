import os
import secrets
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

# Secure Environmental Variable Retrieval
_raw_key = os.getenv("FERNET_KEY")
if not _raw_key:
    raise ValueError("Encryption Context CRITICAL: FERNET_KEY environment variable is missing!")

# Coerce any key string securely into an exact 256-bit (32 byte) deterministic footprint
_aes_master_key = hashlib.sha256(_raw_key.encode()).digest()
_aesgcm = AESGCM(_aes_master_key)


def encrypt_field(value: str) -> str:
    """
    Encrypts plaintext natively using AES-256-GCM.
    Generates a cryptographically strong 96-bit randomized nonce.
    Appends the nonce sequentially to the ciphertext for DB transport.
    """
    plaintext_bytes = value.encode('utf-8')
    nonce = secrets.token_bytes(12)  # 96-bit CSPRNG Nonce
    ciphertext = _aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    # Store Nonce + Ciphertext (The GCM auth tag is automatically appended by the cipher physically)
    combined = nonce + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_field(token: str) -> str:
    """
    Decrypts the AES-256-GCM ciphertext matrix.
    If the text has been altered, the Galois Message Authentication Code logically fails and throws a fatal exception.
    """
    try:
        raw_combined = base64.b64decode(token.encode('utf-8'))
        nonce = raw_combined[:12]
        ciphertext = raw_combined[12:]
        
        # This will explicitly throw cryptography.exceptions.InvalidTag if tampered!
        plaintext_bytes = _aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        # FIPS 140-2 requirement: Modules must physically fail securely!
        raise ValueError(f"CRITICAL TAMPER ALERT: Decryption forcefully halted. Invalid AES-GCM Auth Tag payload. Exception details: {str(e)}")
