"""Unit tests for audit logger."""
import pytest
from qameleon.key_management.audit_logger import AuditLogger, AuditEventType


@pytest.mark.unit
class TestAuditLogger:
    def test_log_entry(self):
        logger = AuditLogger()
        entry = logger.log(AuditEventType.KEY_GENERATED, "user1", "k1")
        assert entry.event_type == AuditEventType.KEY_GENERATED
        assert entry.actor == "user1"
        assert entry.key_id == "k1"

    def test_chain_integrity(self):
        logger = AuditLogger()
        for i in range(5):
            logger.log(AuditEventType.KEY_STORED, "user1", f"k{i}")
        assert logger.verify_chain()

    def test_chain_tamper_detection(self):
        logger = AuditLogger()
        logger.log(AuditEventType.KEY_GENERATED, "user1", "k1")
        entry = logger.get_entries()[0]
        entry.entry_hash = b"\x00" * 32
        assert not logger.verify_chain()

    def test_filter_by_event_type(self):
        logger = AuditLogger()
        logger.log(AuditEventType.KEY_GENERATED, "u", "k1")
        logger.log(AuditEventType.KEY_DESTROYED, "u", "k2")
        entries = logger.get_entries(event_type=AuditEventType.KEY_GENERATED)
        assert len(entries) == 1
