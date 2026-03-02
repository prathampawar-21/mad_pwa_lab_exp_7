"""QHP handshake state machine."""

from enum import Enum, auto

from qameleon.exceptions import InvalidStateTransitionError


class HandshakeState(Enum):
    """QHP handshake states."""
    INIT = auto()
    HELLO_SENT = auto()
    HELLO_RECEIVED = auto()
    NEGOTIATED = auto()
    KEY_INIT_SENT = auto()
    KEY_RESP_SENT = auto()
    ESTABLISHED = auto()
    REKEYING = auto()
    TERMINATED = auto()


# Valid state transitions
_VALID_TRANSITIONS: dict[HandshakeState, set[HandshakeState]] = {
    HandshakeState.INIT: {HandshakeState.HELLO_SENT, HandshakeState.HELLO_RECEIVED},
    HandshakeState.HELLO_SENT: {HandshakeState.NEGOTIATED, HandshakeState.TERMINATED},
    HandshakeState.HELLO_RECEIVED: {HandshakeState.NEGOTIATED, HandshakeState.TERMINATED},
    HandshakeState.NEGOTIATED: {HandshakeState.KEY_INIT_SENT, HandshakeState.KEY_RESP_SENT},
    HandshakeState.KEY_INIT_SENT: {HandshakeState.ESTABLISHED, HandshakeState.TERMINATED},
    HandshakeState.KEY_RESP_SENT: {HandshakeState.ESTABLISHED, HandshakeState.TERMINATED},
    HandshakeState.ESTABLISHED: {HandshakeState.REKEYING, HandshakeState.TERMINATED},
    HandshakeState.REKEYING: {HandshakeState.ESTABLISHED, HandshakeState.TERMINATED},
    HandshakeState.TERMINATED: set(),
}


class HandshakeStateMachine:
    """Validates QHP handshake state transitions."""

    def __init__(self) -> None:
        self.state = HandshakeState.INIT

    def transition(self, new_state: HandshakeState) -> None:
        """Transition to a new state, raising on invalid transitions."""
        valid = _VALID_TRANSITIONS.get(self.state, set())
        if new_state not in valid:
            raise InvalidStateTransitionError(
                f"Invalid transition: {self.state.name} -> {new_state.name}"
            )
        self.state = new_state

    def is_established(self) -> bool:
        return self.state == HandshakeState.ESTABLISHED

    def is_terminated(self) -> bool:
        return self.state == HandshakeState.TERMINATED
