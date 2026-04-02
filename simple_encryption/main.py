from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

class AesPassphraseEncryptor:
    """
    Encrypt any bytes data with a custom passphrase
    Algorithm: AES-256-GCM (Highest security level)
    Encryption output: Base64 string
    """

    @staticmethod
    def _passphrase_to_key(passphrase: str, salt: bytes) -> bytes:
        """Securely convert a custom passphrase to a 32-byte AES-256 key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def encrypt(data: bytes, passphrase: str) -> str:
        """
        Encrypt any bytes data
        :param data: Original bytes
        :param passphrase: Your custom passphrase
        :return: Encrypted Base64 string
        """
        salt = os.urandom(16)    # Random salt
        nonce = os.urandom(12)   # GCM nonce
        key = AesPassphraseEncryptor._passphrase_to_key(passphrase, salt)

        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Pack format: salt(16) + nonce(12) + tag(16) + ciphertext
        encrypted_bytes = salt + nonce + encryptor.tag + ciphertext
        
        # Convert to Base64
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    @staticmethod
    def decrypt(encrypted_base64: str, passphrase: str) -> bytes:
        """
        Decrypt
        :param encrypted_base64: Encrypted Base64 string
        :param passphrase: Your passphrase
        :return: Original bytes
        """
        # Base64 decode back to bytes
        encrypted_data = base64.b64decode(encrypted_base64)
        
        # Automatically unpack data
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]

        # Convert passphrase to key
        key = AesPassphraseEncryptor._passphrase_to_key(passphrase, salt)

        # Decrypt + verify integrity
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
