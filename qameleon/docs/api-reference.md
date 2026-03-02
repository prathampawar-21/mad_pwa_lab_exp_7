# QAMELEON API Reference

## ML-KEM

```python
from qameleon.crypto_primitives.ml_kem import MLKEM

kem = MLKEM(security_level=768)  # or 512, 1024
keypair = kem.keygen()           # -> MLKEMKeyPair
result = kem.encaps(keypair.public_key)  # -> MLKEMEncapsResult
ss = kem.decaps(keypair.secret_key, result.ciphertext)  # -> bytes
```

## ML-DSA

```python
from qameleon.crypto_primitives.ml_dsa import MLDSA

dsa = MLDSA(security_level=65)  # or 44, 87
keypair = dsa.keygen()
sig = dsa.sign(keypair.secret_key, message)
valid = dsa.verify(keypair.public_key, message, sig)
```

## Hybrid KEM

```python
from qameleon.crypto_primitives.hybrid_kem import HybridKEM

kem = HybridKEM(security_level=768)
kp = kem.keygen()
result = kem.encaps(kp.public_key)
ss = kem.decaps(kp.secret_key, result)
```

## SecureSession

```python
from qameleon.protocol.session import SecureSession

session = SecureSession(master_key, session_id)
payload = session.encrypt(plaintext, aad)
plaintext = session.decrypt(payload)
session.destroy()
```

## Dashboard

```python
from qameleon.dashboard.app import create_dashboard_app
import uvicorn

app = create_dashboard_app()
uvicorn.run(app, host="0.0.0.0", port=8000)
```
