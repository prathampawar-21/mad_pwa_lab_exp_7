"""Integration test: complete QHP handshake."""
import pytest
from qameleon.mesh_network.mesh_node import MeshNode


@pytest.mark.integration
class TestFullHandshake:
    def test_complete_handshake(self):
        alice = MeshNode("alice", classification_level=0)
        bob = MeshNode("bob", classification_level=0)
        alice.initialize()
        bob.initialize()

        # Phase 1: HELLO
        hello = alice.initiate_handshake("bob")
        response = bob.respond_to_hello(hello, "alice")

        # Phase 2: KEY_INIT
        key_init = alice.process_hello_response_and_send_key_init(response, "bob")

        # Phase 3: KEY_RESPONSE
        key_response = bob.process_key_init_and_respond(key_init, "alice")

        # Phase 4: Finalize
        alice_session = alice.finalize_initiator_session(key_response, "bob")
        bob_session = bob.finalize_responder_session("alice")

        assert alice_session is not None
        assert bob_session is not None

        # Test encrypted communication
        plaintext = b"Hello, post-quantum world!"
        payload = alice_session.encrypt(plaintext)
        recovered = bob_session.decrypt(payload)
        assert recovered == plaintext

    def test_session_statistics(self):
        alice = MeshNode("alice2", 0)
        bob = MeshNode("bob2", 0)
        alice.initialize()
        bob.initialize()

        hello = alice.initiate_handshake("bob2")
        response = bob.respond_to_hello(hello, "alice2")
        key_init = alice.process_hello_response_and_send_key_init(response, "bob2")
        key_response = bob.process_key_init_and_respond(key_init, "alice2")
        alice_session = alice.finalize_initiator_session(key_response, "bob2")

        alice_session.encrypt(b"data")
        stats = alice_session.get_stats()
        assert stats.messages_sent == 1
