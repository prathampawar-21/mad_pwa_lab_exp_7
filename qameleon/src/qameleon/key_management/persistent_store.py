"""Persistent key store with AES-256-GCM encryption."""

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from qameleon.crypto_primitives.symmetric import SymmetricCipher, EncryptedPayload
from qameleon.key_management.key_store import KeyStore, KeyEntry, KeyState

# File format: [16-byte random salt][12-byte nonce][ciphertext]
_SALT_LEN = 16


class PersistentKeyStore(KeyStore):
    """Key store that persists encrypted keys to disk."""

    PBKDF2_ITERATIONS = 600_000

    def __init__(self, path: str, password: str) -> None:
        super().__init__()
        self._path = Path(path)
        self._password = password
        if self._path.exists():
            self.load()

    def _derive_master_key(self, password: str, salt: bytes) -> bytes:
        """Derive master key using PBKDF2-SHA256 with a provided salt."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            self.PBKDF2_ITERATIONS,
            dklen=32,
        )

    def save(self) -> None:
        """Encrypt and save all keys to disk."""
        with self._lock:
            data = {}
            for key_id, entry in self._keys.items():
                data[key_id] = {
                    "key_material": entry.key_material.hex(),
                    "state": entry.state.value,
                    "algorithm": entry.algorithm,
                    "classification_level": entry.classification_level,
                    "created_at": entry.created_at,
                    "expires_at": entry.expires_at,
                    "rotated_from": entry.rotated_from,
                }
            plaintext = json.dumps(data).encode()
            salt = os.urandom(_SALT_LEN)
            master_key = self._derive_master_key(self._password, salt)
            payload = SymmetricCipher.encrypt(master_key, plaintext)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "wb") as f:
                f.write(salt + payload.nonce + payload.ciphertext)

    def load(self) -> None:
        """Load and decrypt keys from disk."""
        try:
            with open(self._path, "rb") as f:
                raw = f.read()
            salt = raw[:_SALT_LEN]
            nonce = raw[_SALT_LEN:_SALT_LEN + 12]
            ciphertext = raw[_SALT_LEN + 12:]
            master_key = self._derive_master_key(self._password, salt)
            payload = EncryptedPayload(nonce=nonce, ciphertext=ciphertext, aad=b"")
            plaintext = SymmetricCipher.decrypt(master_key, payload)
            data = json.loads(plaintext.decode())

            with self._lock:
                for key_id, entry_data in data.items():
                    self._keys[key_id] = KeyEntry(
                        key_id=key_id,
                        key_material=bytes.fromhex(entry_data["key_material"]),
                        state=KeyState(entry_data["state"]),
                        algorithm=entry_data["algorithm"],
                        classification_level=entry_data["classification_level"],
                        created_at=entry_data["created_at"],
                        expires_at=entry_data.get("expires_at"),
                        rotated_from=entry_data.get("rotated_from"),
                    )
        except Exception:
            pass  # Start fresh if load fails

    def delete(self, key_id: str) -> None:
        """Delete a key from the store."""
        self.destroy(key_id)
        with self._lock:
            self._keys.pop(key_id, None)

    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password. Re-saves with a new random salt."""
        old_key_candidate = self._derive_master_key(old_password, b"verify")
        # Re-derive from stored file to verify old password
        if self._path.exists():
            try:
                with open(self._path, "rb") as f:
                    raw = f.read()
                salt = raw[:_SALT_LEN]
                nonce = raw[_SALT_LEN:_SALT_LEN + 12]
                ciphertext = raw[_SALT_LEN + 12:]
                old_master_key = self._derive_master_key(old_password, salt)
                payload = EncryptedPayload(nonce=nonce, ciphertext=ciphertext, aad=b"")
                SymmetricCipher.decrypt(old_master_key, payload)  # raises on wrong password
            except Exception:
                return False
        self._password = new_password
        self.save()
        return True

