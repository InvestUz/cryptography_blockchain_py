# encryption.py

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class EncryptionManager:
    """
    This class handles data encryption and decryption using AES-GCM.
    """

    def __init__(self):
        # Key could be derived from a passphrase or could be randomly generated.
        # For demonstration, we generate a random key each run, 
        # but in production store it safely (vault, environment variable, HSM, etc.).
        self.aes_key = AESGCM.generate_key(bit_length=256)

    def encrypt_data(self, plaintext: str) -> dict:
        """
        Encrypts a plaintext string with AES-GCM.
        
        Returns a dictionary with:
          - nonce
          - ciphertext
          - tag (GCM tag is embedded within AESGCM library’s output, but we demonstrate 
            storing extra data if needed)
        """
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)  # AES-GCM recommended 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_data(self, nonce: str, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext with AES-GCM.
        """
        aesgcm = AESGCM(self.aes_key)
        nonce_bytes = base64.b64decode(nonce.encode('utf-8'))
        ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))

        plaintext_bytes = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)
        return plaintext_bytes.decode('utf-8')
