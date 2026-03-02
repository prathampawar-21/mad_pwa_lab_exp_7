"""QAMELEON exception hierarchy."""


class QAMELEONError(Exception):
    """Base exception for all QAMELEON errors."""


class KeyGenerationError(QAMELEONError):
    """Raised when key generation fails."""


class EncapsulationError(QAMELEONError):
    """Raised when KEM encapsulation fails."""


class DecapsulationError(QAMELEONError):
    """Raised when KEM decapsulation fails."""


class SignatureError(QAMELEONError):
    """Raised when signature creation fails."""


class VerificationError(QAMELEONError):
    """Raised when signature verification fails."""


class UnsupportedAlgorithmError(QAMELEONError):
    """Raised when an unsupported algorithm is requested."""


class DowngradeAttemptError(QAMELEONError):
    """Raised when a cryptographic downgrade attempt is detected."""


class PolicyViolationError(QAMELEONError):
    """Raised when a security policy is violated."""


class ClassificationViolationError(QAMELEONError):
    """Raised when a classification boundary is violated."""


class CrossDomainDeniedError(QAMELEONError):
    """Raised when cross-domain data flow is denied."""


class HandshakeError(QAMELEONError):
    """Raised when the QHP handshake fails."""


class InvalidMessageError(QAMELEONError):
    """Raised when a message is malformed or invalid."""


class ReplayDetectedError(QAMELEONError):
    """Raised when a message replay attack is detected."""


class SessionExpiredError(QAMELEONError):
    """Raised when a session has expired."""


class InvalidStateTransitionError(QAMELEONError):
    """Raised when an invalid state machine transition is attempted."""
