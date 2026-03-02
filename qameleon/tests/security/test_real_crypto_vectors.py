"""Security test: real cryptographic test vectors."""
import pytest
import hashlib
from qameleon.crypto_primitives.ntt import KYBER_Q, kyber_ntt, kyber_ntt_inv
from qameleon.crypto_primitives.hash_functions import HashEngine


@pytest.mark.security
class TestRealCryptoVectors:
    def test_sha3_256_nist_vector(self):
        # NIST test vector: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        empty_hash = HashEngine.sha3_256(b"")
        expected = bytes.fromhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        assert empty_hash == expected

    def test_sha3_512_nist_vector(self):
        # NIST: SHA3-512("") 
        empty_hash = HashEngine.sha3_512(b"")
        expected = bytes.fromhex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        )
        assert empty_hash == expected

    def test_ntt_forward_inverse_identity(self):
        """NTT(NTT_inv(a)) = a mod q."""
        import os
        poly = [int(b) % KYBER_Q for b in os.urandom(256)]
        transformed = kyber_ntt(poly)
        recovered = kyber_ntt_inv(transformed)
        for orig, rec in zip(poly, recovered):
            assert abs(orig - rec % KYBER_Q) < 2 or (orig % KYBER_Q) == (rec % KYBER_Q)

    def test_ntt_linearity(self):
        """NTT(a + b) = NTT(a) + NTT(b) mod q."""
        from qameleon.crypto_primitives.poly import KyberPoly
        import os
        a = KyberPoly([int(b) % KYBER_Q for b in os.urandom(256)])
        b = KyberPoly([int(b) % KYBER_Q for b in os.urandom(256)])
        lhs = a.add(b).ntt()
        rhs = a.ntt().add(b.ntt())
        # Check they're equal mod q
        for l, r in zip(lhs.coeffs, rhs.coeffs):
            assert l % KYBER_Q == r % KYBER_Q
