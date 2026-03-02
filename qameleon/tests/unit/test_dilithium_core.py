"""Unit tests for Dilithium core."""
import pytest
from qameleon.crypto_primitives.dilithium_core import (
    DilithiumParams, dilithium_keygen, dilithium_sign, dilithium_verify,
)


@pytest.mark.unit
class TestDilithiumCore:
    def test_keygen_65(self):
        params = DilithiumParams.level_65()
        pk, sk = dilithium_keygen(params)
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    def test_sign_verify_65(self):
        params = DilithiumParams.level_65()
        pk, sk = dilithium_keygen(params)
        sig = dilithium_sign(params, sk, b"test")
        assert dilithium_verify(params, pk, b"test", sig)

    def test_verify_wrong_message(self):
        params = DilithiumParams.level_65()
        pk, sk = dilithium_keygen(params)
        sig = dilithium_sign(params, sk, b"original")
        assert not dilithium_verify(params, pk, b"different", sig)

    def test_params_level_44(self):
        params = DilithiumParams.level_44()
        assert params.k == 4
        assert params.l == 4

    def test_params_level_87(self):
        params = DilithiumParams.level_87()
        assert params.k == 8
