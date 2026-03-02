"""Cross-domain gateway enforcing classification boundaries."""

import hashlib
import os
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from qameleon.exceptions import ClassificationViolationError, CrossDomainDeniedError


class ClassificationLevel(IntEnum):
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3
    TOP_SECRET_SCI = 4


@dataclass
class CrossDomainSession:
    """A cross-domain communication session."""
    session_id: str
    source_domain: ClassificationLevel
    target_domain: ClassificationLevel
    session_key: bytes
    created_at: float
    allowed_directions: tuple[ClassificationLevel, ClassificationLevel]


class CrossDomainGateway:
    """Enforces information flow control across classification boundaries."""

    def __init__(self) -> None:
        self._sessions: dict[str, CrossDomainSession] = {}

    def create_session(
        self,
        source: ClassificationLevel,
        target: ClassificationLevel,
    ) -> CrossDomainSession:
        """Create a cross-domain session.
        
        Raises ClassificationViolationError if write-down is attempted.
        """
        # Prevent write-down: can only flow to equal or higher classification
        if target < source:
            raise ClassificationViolationError(
                f"Write-down attempt: {source.name} -> {target.name} is forbidden"
            )

        session_id = os.urandom(16).hex()
        # Derive domain-specific key
        session_key = hashlib.sha3_256(
            b"CROSS-DOMAIN-SESSION"
            + source.value.to_bytes(1, 'big')
            + target.value.to_bytes(1, 'big')
            + session_id.encode()
        ).digest()

        session = CrossDomainSession(
            session_id=session_id,
            source_domain=source,
            target_domain=target,
            session_key=session_key,
            created_at=time.time(),
            allowed_directions=(source, target),
        )
        self._sessions[session_id] = session
        return session

    def validate_data_flow(
        self,
        session_id: str,
        data_classification: ClassificationLevel,
        direction: str = "source_to_target",
    ) -> bool:
        """Validate that data flow respects classification boundaries."""
        session = self._sessions.get(session_id)
        if session is None:
            raise CrossDomainDeniedError(f"Session {session_id} not found")

        if direction == "source_to_target":
            if data_classification > session.target_domain:
                raise ClassificationViolationError(
                    f"Data classification {data_classification.name} exceeds "
                    f"target domain {session.target_domain.name}"
                )
        return True

    def close_session(self, session_id: str) -> None:
        """Close a cross-domain session."""
        session = self._sessions.pop(session_id, None)
        if session:
            # Zeroize session key
            session.session_key = b"\x00" * len(session.session_key)
