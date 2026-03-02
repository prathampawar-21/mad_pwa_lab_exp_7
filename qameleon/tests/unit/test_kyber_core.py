"""Unit tests for Kyber core."""
import pytest
from qameleon.crypto_primitives.kyber_core import (
    KyberParams, kyber_keygen, kyber_encaps, kyber_decaps,
)


@pytest.mark.unit
class TestKyberCore:
    def test_keygen_768(self):
        params = KyberParams.level_768()
        pk, sk = kyber_keygen(params)
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    def test_keygen_512(self):
        params = KyberParams.level_512()
        pk, sk = kyber_keygen(params)
        assert len(pk) > 0

    def test_encaps_768(self):
        params = KyberParams.level_768()
        pk, sk = kyber_keygen(params)
        ct, ss = kyber_encaps(params, pk)
        assert isinstance(ct, bytes)
        assert isinstance(ss, bytes)
        assert len(ss) == 32

    def test_decaps_768(self):
        params = KyberParams.level_768()
        pk, sk = kyber_keygen(params)
        ct, ss = kyber_encaps(params, pk)
        recovered = kyber_decaps(params, sk, ct)
        assert len(recovered) == 32

    def test_params_level_1024(self):
        params = KyberParams.level_1024()
        assert params.k == 4
