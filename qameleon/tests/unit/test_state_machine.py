"""Unit tests for handshake state machine."""
import pytest
from qameleon.protocol.state_machine import HandshakeStateMachine, HandshakeState
from qameleon.exceptions import InvalidStateTransitionError


@pytest.mark.unit
class TestStateMachine:
    def test_initial_state(self):
        sm = HandshakeStateMachine()
        assert sm.state == HandshakeState.INIT

    def test_valid_transition(self):
        sm = HandshakeStateMachine()
        sm.transition(HandshakeState.HELLO_SENT)
        assert sm.state == HandshakeState.HELLO_SENT

    def test_invalid_transition_raises(self):
        sm = HandshakeStateMachine()
        with pytest.raises(InvalidStateTransitionError):
            sm.transition(HandshakeState.ESTABLISHED)

    def test_full_initiator_flow(self):
        sm = HandshakeStateMachine()
        sm.transition(HandshakeState.HELLO_SENT)
        sm.transition(HandshakeState.NEGOTIATED)
        sm.transition(HandshakeState.KEY_INIT_SENT)
        sm.transition(HandshakeState.ESTABLISHED)
        assert sm.is_established()

    def test_terminate_from_established(self):
        sm = HandshakeStateMachine()
        sm.transition(HandshakeState.HELLO_SENT)
        sm.transition(HandshakeState.NEGOTIATED)
        sm.transition(HandshakeState.KEY_INIT_SENT)
        sm.transition(HandshakeState.ESTABLISHED)
        sm.transition(HandshakeState.TERMINATED)
        assert sm.is_terminated()
