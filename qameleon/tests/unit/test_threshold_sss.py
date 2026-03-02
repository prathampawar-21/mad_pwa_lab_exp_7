"""Unit tests for Threshold Secret Sharing."""
import pytest
from qameleon.key_management.threshold_sss import ThresholdSecretSharing


@pytest.mark.unit
class TestThresholdSSS:
    def test_split_reconstruct_2_3(self):
        secret = b"secret32byteslong_____00000000ab"
        shares = ThresholdSecretSharing.split(secret, 2, 3)
        assert len(shares) == 3
        recovered = ThresholdSecretSharing.reconstruct(shares[:2])
        assert recovered == secret

    def test_split_reconstruct_3_5(self):
        secret = b"another_secret_key_data_00000000"
        shares = ThresholdSecretSharing.split(secret, 3, 5)
        recovered = ThresholdSecretSharing.reconstruct(shares[:3])
        assert recovered == secret

    def test_insufficient_shares_fails(self):
        secret = b"secret32byteslong_____00000000cd"
        shares = ThresholdSecretSharing.split(secret, 3, 5)
        # With only 1 share, reconstruction should give wrong result
        recovered = ThresholdSecretSharing.reconstruct(shares[:1])
        assert recovered != secret

    def test_all_shares_reconstruct(self):
        secret = b"test_secret_key_32bytes_00000000"
        shares = ThresholdSecretSharing.split(secret, 2, 4)
        recovered = ThresholdSecretSharing.reconstruct(shares)
        assert recovered == secret
