import pytest
import os
import json
from spake.spake import (
    SPAKE2Party,
    SpakeHandshake,
    SecureChannel,
    HKDF,
    HKDF_HASH,
    encode_with_length,
    compute_transcript,
    hash_password,
    b64e,
    decode_edwards_point,
    is_valid_edwards_point,
)
import binascii

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

def test_compute_transcript():
    """Ensure compute_transcript constructs the transcript deterministically."""
    id_A, id_B = "Alice", "Bob"
    pA = os.urandom(32)
    pB = os.urandom(32)
    K = os.urandom(32)
    w = hash_password(b"password")
    
    transcript1 = compute_transcript(id_A, id_B, pA, pB, K, w)
    transcript2 = compute_transcript(id_A, id_B, pA, pB, K, w)

    assert transcript1 == transcript2, "Transcripts must be deterministically constructed"

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

    K_A = alice.compute_shared_secret(bob.pi)
    K_B = bob.compute_shared_secret(alice.pi)

    assert K_A == K_B, "Shared secrets should be identical"
    assert isinstance(K_A, bytes), "Shared secret must be bytes"
    assert len(K_A) == 32, "Shared secret should be 32 bytes"

def test_spake2_key_schedule():
    """Ensure the key derivation process generates correctly sized keys."""
    password = b"testpassword"

    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    K_A = alice.compute_shared_secret(bob.pi)
    transcript = compute_transcript("Alice", "Bob", alice.pi, bob.pi, K_A, alice.w)

    Ke_A, Ka_A, KcA_A, KcB_A = alice.key_schedule(transcript)

    assert len(Ke_A) == 16, "Ke should be 16 bytes"
    assert len(Ka_A) == 16, "Ka should be 16 bytes"
    assert len(KcA_A) == 16, "KcA should be 16 bytes"
    assert len(KcB_A) == 16, "KcB should be 16 bytes"

def test_spake2_confirmation_macs():
    """Ensure confirmation MACs are correctly generated and verified."""
    password = b"testpassword"

    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    K_A = alice.compute_shared_secret(bob.pi)
    transcript = compute_transcript("Alice", "Bob", alice.pi, bob.pi, K_A, alice.w)

    _, _, KcA_A, KcB_A = alice.key_schedule(transcript)
    _, _, KcA_B, KcB_B = bob.key_schedule(transcript)

    conf_A = alice.generate_confirmation(KcA_A, transcript)
    conf_B = bob.generate_confirmation(KcB_B, transcript)

    assert bob.verify_confirmation(conf_A, KcA_A, transcript), "Alice's confirmation should verify"
    assert alice.verify_confirmation(conf_B, KcB_B, transcript), "Bob's confirmation should verify"

# ---- SPAKE2 HANDSHAKE TEST ----

def test_spake2_full_handshake():
    """Test a full SPAKE2 handshake and transcript validation."""
    password = b"testpassword"
    
    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)

    handshake = SpakeHandshake(alice, bob)
    shared_secret, transcript = handshake.run_handshake()

    assert isinstance(shared_secret, bytes), "Shared secret must be bytes"
    assert len(shared_secret) == 16, "Shared secret must be 16 bytes"
    assert isinstance(transcript, bytes), "Transcript must be bytes"

# ---- SECURE CHANNEL TESTS ----

@pytest.fixture
def secure_channel():
    """Fixture to create a secure channel for testing."""
    session_key = os.urandom(32)
    mac_key = os.urandom(32)
    return SecureChannel(session_key, mac_key)

def test_secure_channel_encryption(secure_channel):
    """Ensure messages are encrypted and decrypted correctly."""
    message = b"Hello, encrypted world!"
    encrypted = secure_channel.send_message(message)
    decrypted = secure_channel.receive_message(encrypted)

    assert decrypted == message, "Decrypted message should match the original"

def test_secure_channel_tampering(secure_channel):
    """Modify the encrypted message and ensure HMAC verification fails."""
    message = b"Sensitive data"
    encrypted = secure_channel.send_message(message)

    corrupted_msg = json.loads(encrypted.decode())
    corrupted_msg["ciphertext_b64"] = b64e(b"tampered_data").decode()
    corrupted_msg = json.dumps(corrupted_msg).encode()

    with pytest.raises(ValueError, match="HMAC verification failed"):
        secure_channel.receive_message(corrupted_msg)

def test_secure_channel_nonce_uniqueness(secure_channel):
    """Ensure encryption uses unique nonces."""
    message = b"Hello, secure world!"
    encrypted1 = secure_channel.send_message(message)
    encrypted2 = secure_channel.send_message(message)

    assert encrypted1 != encrypted2, "Encrypted messages should be different"

def test_secure_channel_invalid_json(secure_channel):
    """Ensure receiving invalid JSON raises an error."""
    invalid_json = b"invalid json"
    with pytest.raises(json.JSONDecodeError):
        secure_channel.receive_message(invalid_json)

def test_secure_channel_invalid_hmac_format(secure_channel):
    """Ensure receiving a message with a malformed HMAC value raises an error."""
    message = b"Important message"
    encrypted = secure_channel.send_message(message)

    malformed_data = json.loads(encrypted.decode())
    malformed_data["hmac_b64"] = "invalid_base64"  # Not valid base64
    malformed_data = json.dumps(malformed_data).encode()

    with pytest.raises((binascii.Error, ValueError)):
        secure_channel.receive_message(malformed_data)

def test_spake2_password_mismatch():
    """Ensure that SPAKE2 fails when parties use different passwords."""
    alice = SPAKE2Party("Alice", b"correctpassword", use_m=True)
    bob = SPAKE2Party("Bob", b"wrongpassword", use_m=False)

    handshake = SpakeHandshake(alice, bob)

    with pytest.raises(ValueError, match="Shared secret mismatch!"):
        handshake.run_handshake()

def test_spake2_transcript_modification():
    """Ensure that modifying the transcript invalidates derived keys."""
    alice = SPAKE2Party("Alice", b"securepassword", use_m=True)
    bob = SPAKE2Party("Bob", b"securepassword", use_m=False)

    handshake = SpakeHandshake(alice, bob)
    _, transcript = handshake.run_handshake()

    # Modify transcript slightly
    tampered_transcript = transcript[:-1] + bytes([transcript[-1] ^ 0x01])  # Flip last bit

    Ke, _, _, _ = alice.key_schedule(transcript)
    Ke_tampered, _, _, _ = bob.key_schedule(tampered_transcript)

    assert Ke != Ke_tampered, "Tampered transcript should not yield the same Ke"

def test_encode_with_large_data():
    """Ensure encoding functions work with large inputs."""
    large_data = os.urandom(10_000_000)  # 10 MB of random data
    encoded = encode_with_length(large_data)
    decoded_length = int.from_bytes(encoded[:8], "little")
    assert decoded_length == len(large_data)

def test_multiple_handshakes():
    """Ensure multiple SPAKE2 handshakes run without state leakage."""
    password = b"securepassword"

    prev_secret = None
    for i in range(5):  # Run 5 handshakes
        alice = SPAKE2Party("Alice", password, use_m=True)
        bob = SPAKE2Party("Bob", password, use_m=False)
        handshake = SpakeHandshake(alice, bob)
        shared_secret, _ = handshake.run_handshake()
        
        #print(f"Run {i+1}: {shared_secret.hex()} ({len(shared_secret)} bytes)")

        assert isinstance(shared_secret, bytes) and len(shared_secret) == 16

        # Ensure no two runs return the same shared secret (with very high probability)
        if prev_secret:
            assert shared_secret != prev_secret, "Shared secret should be different in each handshake!"
        prev_secret = shared_secret

# ---- RUNNING THE TEST SUITE ----
if __name__ == "__main__":
    pytest.main()
