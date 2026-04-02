# simple-encryption
a simple encryption lib for bytes data.

## Installation

```bash
pip install simple-encryption
```

## Usage

```python
from simple_encryption import AesPassphraseEncryptor

passphrase = "my_secrete_key"
original_data = b"hello world!"

# encrypt bytes data into base64 data
b64_encrypted = AesPassphraseEncryptor.encrypt(original_data, passphrase)
print("encrypted data:", b64_encrypted)

# decrypt base64 data into original bytes data
decrypted_data = AesPassphraseEncryptor.decrypt(b64_encrypted, passphrase)
assert original_data == decrypted_data
```
