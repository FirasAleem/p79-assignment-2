import pytest
import os
import json
import binascii
from spake2.spake2 import (
    SPAKE2Party,
    SPAKE2Handshake,
    SecureChannel,
    encode_with_length,
    hash_password,
    b64e,
    decode_edwards_point,
    is_valid_edwards_point,
)

# ---- UTILITY FUNCTION TESTS ----

def test_hash_password():
    """Ensure hash_password produces a valid w within the expected range."""
    password = b"securepassword"
    w = hash_password(password)
    assert isinstance(w, int), "w should be an integer"
    assert 0 <= w < (2**252 + 27742317777372353535851937790883648493), "w must be in the correct range"

def test_encode_with_length():
    """Verify that encode_with_length produces a correct length prefix."""
    data = b"test data"
    encoded = encode_with_length(data)
    
    length_prefix = encoded[:8]
    length_value = int.from_bytes(length_prefix, "little")
    
    assert length_value == len(data), "Encoded length prefix should match data length"
    assert encoded[8:] == data, "Encoded value should contain the original data"

# ---- SPAKE2 PARTY TESTS ----

def test_spake2_public_message_validity():
    """Ensure the computed public message belongs to the correct group."""
    password = b"testpassword"
    
    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    pA_point = decode_edwards_point(alice.pi)
    pB_point = decode_edwards_point(bob.pi)

    assert is_valid_edwards_point(pA_point), "Alice's public message should be in the correct subgroup"
    assert is_valid_edwards_point(pB_point), "Bob's public message should be in the correct subgroup"

def test_spake2_shared_secret():
    """Ensure two parties compute identical shared secrets."""
    password = b"testpassword"
    
    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    alice.receive_peer_message(bob.pi, "Bob")
    bob.receive_peer_message(alice.pi, "Alice")

    K_A = alice.compute_shared_secret()
    K_B = bob.compute_shared_secret()

    assert K_A == K_B, "Shared secrets should be identical"
    assert isinstance(K_A, bytes), "Shared secret must be bytes"
    assert len(K_A) == 32, "Shared secret should be 32 bytes"

def test_spake2_key_schedule():
    """Ensure the key derivation process generates correctly sized keys."""
    password = b"testpassword"

    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    alice.receive_peer_message(bob.pi, "Bob")
    bob.receive_peer_message(alice.pi, "Alice")

    alice.compute_shared_secret()
    bob.compute_shared_secret()

    Ke_A, Ka_A, KcA_A, KcB_A = alice.key_schedule()

    assert len(Ke_A) == 16, "Ke should be 16 bytes"
    assert len(Ka_A) == 16, "Ka should be 16 bytes"
    assert len(KcA_A) == 16, "KcA should be 16 bytes"
    assert len(KcB_A) == 16, "KcB should be 16 bytes"

def test_spake2_confirmation_macs():
    """Ensure confirmation MACs are correctly generated and verified."""
    password = b"testpassword"

    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    alice.receive_peer_message(bob.pi, "Bob")
    bob.receive_peer_message(alice.pi, "Alice")

    alice.compute_shared_secret()
    bob.compute_shared_secret()

    _, _, KcA_A, KcB_A = alice.key_schedule()
    _, _, KcA_B, KcB_B = bob.key_schedule()

    conf_A = alice.generate_confirmation(KcA_A)
    conf_B = bob.generate_confirmation(KcB_B)

    bob.store_peer_confirmation(conf_A)
    alice.store_peer_confirmation(conf_B)

    assert bob.verify_peer_confirmation(KcA_A), "Alice's confirmation should verify"
    assert alice.verify_peer_confirmation(KcB_B), "Bob's confirmation should verify"


# ---- SPAKE2 HANDSHAKE TEST ----

def test_spake2_full_handshake():
    """Test a full SPAKE2 handshake and transcript validation."""
    password = b"testpassword"
    
    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    handshake = SPAKE2Handshake(alice, bob)
    shared_secret, transcript = handshake.run_handshake()

    assert isinstance(shared_secret, bytes), "Shared secret must be bytes"
    assert len(shared_secret) == 16, "Shared secret must be 16 bytes"
    assert isinstance(transcript, bytes), "Transcript must be bytes"


# ---- SECURE CHANNEL TESTS ----

@pytest.fixture
def secure_channel():
    """Fixture to create a secure channel for testing."""
    session_key = os.urandom(32)
    return SecureChannel(session_key)

def test_secure_channel_encryption(secure_channel):
    """Ensure messages are encrypted and decrypted correctly."""
    message = b"Hello, encrypted world!"
    encrypted = secure_channel.send_message(message)
    decrypted = secure_channel.receive_message(encrypted)

    assert decrypted == message, "Decrypted message should match the original"


# ---- EDGE CASE TESTS ----

def test_spake2_password_mismatch():
    """Ensure that SPAKE2 fails when parties use different passwords."""
    alice = SPAKE2Party("Alice", b"correctpassword", use_m=True)
    bob = SPAKE2Party("Bob", b"wrongpassword", use_m=False)

    handshake = SPAKE2Handshake(alice, bob)

    with pytest.raises(ValueError, match="Shared secret mismatch!"):
        handshake.run_handshake()


def test_multiple_handshakes():
    """Ensure multiple SPAKE2 handshakes run without state leakage."""
    password = b"securepassword"

    prev_secret = None
    for i in range(5):  # Run 5 handshakes
        alice = SPAKE2Party("Alice", password, use_m=True)
        bob = SPAKE2Party("Bob", password, use_m=False)
        handshake = SPAKE2Handshake(alice, bob)
        shared_secret, _ = handshake.run_handshake()

        assert isinstance(shared_secret, bytes) and len(shared_secret) == 16

        if prev_secret:
            assert shared_secret != prev_secret, "Shared secret should be different in each handshake!"
        prev_secret = shared_secret


# ---- RUNNING THE TEST SUITE ----
if __name__ == "__main__":
    pytest.main()
