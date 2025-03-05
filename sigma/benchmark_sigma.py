import time
import statistics
import os
import base64

# (Assume your implementations of Certificate, CertificateAuthority, SigmaParty,
# SigmaHandshake, SigmaKeys, and SecureChannel are already defined as in your code.)

from sigma import CertificateAuthority, SigmaParty, SigmaHandshake, SecureChannel
from ed25519.ed25519 import SigningKey, VerifyingKey
from x25519.x25519 import X25519PrivateKey, X25519PublicKey

# Alias for base64 encoding/decoding
b64e = base64.b64encode
b64d = base64.b64decode

def benchmark_sigma_handshake(num_iter: int = 100, warmup: int = 10) -> None:
    """
    Benchmark the complete SIGMA handshake over num_iter iterations,
    with a warm-up phase of 'warmup' iterations. Measures the total time for
    handshake (steps 1-4) and prints average, median, standard deviation,
    min, and max durations.
    """
    # Warm-up phase to mitigate startup overhead:
    ca = CertificateAuthority("BenchmarkCA")
    ca_public_key = ca.public_key
    for _ in range(warmup):
        alice = SigmaParty("Alice", ca_public_key)
        bob = SigmaParty("Bob", ca_public_key)
        alice_cert = ca.issue_certificate("Alice", alice.ed25519_public)
        bob_cert = ca.issue_certificate("Bob", bob.ed25519_public)
        alice.set_certificate(alice_cert)
        bob.set_certificate(bob_cert)
        handshake = SigmaHandshake(alice, bob)
        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
        _ = handshake.finalize_handshake(sigma_final_msg)

    durations = []
    for _ in range(num_iter):
        alice = SigmaParty("Alice", ca_public_key)
        bob = SigmaParty("Bob", ca_public_key)
        alice_cert = ca.issue_certificate("Alice", alice.ed25519_public)
        bob_cert = ca.issue_certificate("Bob", bob.ed25519_public)
        alice.set_certificate(alice_cert)
        bob.set_certificate(bob_cert)
        handshake = SigmaHandshake(alice, bob)
        start = time.perf_counter()
        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
        _ = handshake.finalize_handshake(sigma_final_msg)
        end = time.perf_counter()
        durations.append(end - start)

    avg_time = statistics.mean(durations)
    median_time = statistics.median(durations)
    stdev_time = statistics.stdev(durations) if len(durations) > 1 else 0
    min_time = min(durations)
    max_time = max(durations)
    print(f"SIGMA handshake benchmark over {num_iter} iterations:")
    print(f"  Average time: {avg_time:.6f} sec")
    print(f"  Median time:  {median_time:.6f} sec")
    print(f"  Std deviation: {stdev_time:.6f} sec")
    print(f"  Min time:     {min_time:.6f} sec, Max time: {max_time:.6f} sec")


def benchmark_secure_channel(num_iter: int = 1000, warmup: int = 100) -> None:
    """
    Benchmark the secure channel round-trip (encryption + decryption)
    over num_iter iterations, with warmup iterations.
    Reports average, median, standard deviation, min, and max durations.
    """
    # Warm-up phase:
    session_key = os.urandom(32)
    mac_key = os.urandom(32)
    channel = SecureChannel(session_key, mac_key)
    message = b"Performance test message for secure channel."

    for _ in range(warmup):
        encrypted = channel.send_message(message)
        _ = channel.receive_message(encrypted)

    durations = []
    for _ in range(num_iter):
        start = time.perf_counter()
        encrypted = channel.send_message(message)
        decrypted = channel.receive_message(encrypted)
        end = time.perf_counter()
        # Ensure correctness.
        assert decrypted == message
        durations.append(end - start)

    avg_time = statistics.mean(durations)
    median_time = statistics.median(durations)
    stdev_time = statistics.stdev(durations) if len(durations) > 1 else 0
    min_time = min(durations)
    max_time = max(durations)
    print(f"Secure channel round-trip benchmark over {num_iter} iterations:")
    print(f"  Average time: {avg_time:.6f} sec")
    print(f"  Median time:  {median_time:.6f} sec")
    print(f"  Std deviation: {stdev_time:.6f} sec")
    print(f"  Min time:     {min_time:.6f} sec, Max time: {max_time:.6f} sec")

def benchmark_signature(num_iter: int = 10000):
    sk = SigningKey.generate()
    vk = sk.generate_verifying_key()
    message = b"Benchmarking Ed25519 signatures"

    start = time.perf_counter()
    for _ in range(num_iter):
        signature = sk.sign(message)
        assert vk.verify(message, signature)
    end = time.perf_counter()

    print(f"Ed25519 Signing+Verification: {(end - start) / num_iter:.6f} sec per operation")

def benchmark_key_exchange(num_iter: int = 10000):
    priv1 = X25519PrivateKey.generate()
    priv2 = X25519PrivateKey.generate()
    pub1 = X25519PublicKey.from_private_key(priv1)
    pub2 = X25519PublicKey.from_private_key(priv2)

    start = time.perf_counter()
    for _ in range(num_iter):
        _ = priv1.exchange(pub2)
        _ = priv2.exchange(pub1)
    end = time.perf_counter()

    print(f"X25519 Key Exchange: {(end - start) / num_iter:.6f} sec per operation")

def benchmark_message_size_effect():
    session_key = os.urandom(32)
    mac_key = os.urandom(32)
    channel = SecureChannel(session_key, mac_key)

    small_msg = b"A" * 64
    large_msg = b"A" * 1024 * 1024  # 1MB

    start = time.perf_counter()
    encrypted_small = channel.send_message(small_msg)
    decrypted_small = channel.receive_message(encrypted_small)
    end = time.perf_counter()
    print(f"Encryption+Decryption (64 bytes): {end - start:.6f} sec")

    start = time.perf_counter()
    encrypted_large = channel.send_message(large_msg)
    decrypted_large = channel.receive_message(encrypted_large)
    end = time.perf_counter()
    print(f"Encryption+Decryption (1MB): {end - start:.6f} sec")

    assert decrypted_small == small_msg
    assert decrypted_large == large_msg

def benchmark_ed25519_signing_verification(num_iter=10000):
    sk = SigningKey.generate()
    vk = sk.generate_verifying_key()
    message = b"Benchmarking Ed25519"

    start = time.perf_counter()
    for _ in range(num_iter):
        signature = sk.sign(message)
    end = time.perf_counter()
    print(f"Ed25519 Signing: {(end - start) / num_iter:.6f} sec per operation")

    signature = sk.sign(message)  # Pre-sign once
    start = time.perf_counter()
    for _ in range(num_iter):
        assert vk.verify(message, signature)
    end = time.perf_counter()
    print(f"Ed25519 Verification: {(end - start) / num_iter:.6f} sec per operation")


def benchmark_sigma_steps(num_iter: int = 1000, warmup: int = 50):
    """
    Benchmark individual steps of the SIGMA handshake over multiple iterations.
    Measures:
        - SIGMA_INIT (Initiator message creation)
        - SIGMA_RESP (Responder processing & response)
        - SIGMA_FINAL (Initiator final processing)
        - Handshake Completion (Responder final processing)
    Reports average, median, standard deviation, min, and max times for each step.
    """

    ca = CertificateAuthority("BenchmarkCA")
    ca_public_key = ca.public_key

    # Warm-up phase to mitigate startup overhead
    for _ in range(warmup):
        alice = SigmaParty("Alice", ca_public_key)
        bob = SigmaParty("Bob", ca_public_key)
        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))
        handshake = SigmaHandshake(alice, bob)
        handshake.process_response_message(handshake.handle_initiation_message(handshake.create_initiation_message()))
        handshake.finalize_handshake(handshake.process_response_message(handshake.handle_initiation_message(handshake.create_initiation_message())))

    # Storage for benchmark times
    init_times, resp_times, final_times, complete_times = [], [], [], []

    for _ in range(num_iter):
        alice = SigmaParty("Alice", ca_public_key)
        bob = SigmaParty("Bob", ca_public_key)
        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))
        handshake = SigmaHandshake(alice, bob)

        # Measure SIGMA_INIT step
        start = time.perf_counter()
        sigma_init_msg = handshake.create_initiation_message()
        init_times.append(time.perf_counter() - start)

        # Measure SIGMA_RESP step
        start = time.perf_counter()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
        resp_times.append(time.perf_counter() - start)

        # Measure SIGMA_FINAL step
        start = time.perf_counter()
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
        final_times.append(time.perf_counter() - start)

        # Measure handshake completion
        start = time.perf_counter()
        handshake.finalize_handshake(sigma_final_msg)
        complete_times.append(time.perf_counter() - start)

    def print_results(name, times):
        print(f"{name} benchmark over {num_iter} iterations:")
        print(f"  Average time: {statistics.mean(times):.6f} sec")
        print(f"  Median time:  {statistics.median(times):.6f} sec")
        print(f"  Std deviation: {statistics.stdev(times) if len(times) > 1 else 0:.6f} sec")
        print(f"  Min time:     {min(times):.6f} sec, Max time: {max(times):.6f} sec")
        print("")

    print("SIGMA protocol step-by-step benchmarking results:\n")
    print_results("Initiation (Alice sends SIGMA_INIT)", init_times)
    print_results("Response (Bob processes INIT, sends SIGMA_RESP)", resp_times)
    print_results("Finalization (Alice processes RESP, sends SIGMA_FINAL)", final_times)
    print_results("Handshake completion (Bob processes FINAL)", complete_times)
    


def main_benchmarks():
    print("Running SIGMA handshake benchmark...")
    benchmark_sigma_handshake(num_iter=100, warmup=5)

    print("\nRunning secure channel benchmark...")
    benchmark_secure_channel(num_iter=1000, warmup=50)
    
    print("\nRunning Ed25519 signature benchmark...")
    benchmark_signature(num_iter=1000)
    
    print("\nRunning Ed25519 signing/verification benchmark...")
    benchmark_ed25519_signing_verification(num_iter=1000)
    
    print("\nRunning X25519 key exchange benchmark...")
    benchmark_key_exchange(num_iter=1000)
    
    print("\nRunning SIGMA handshake step-by-step benchmark...")
    benchmark_sigma_steps(num_iter=100, warmup=5)
    
    print("\nBenchmarking effect of message size on encryption/decryption...")
    benchmark_message_size_effect()


if __name__ == "__main__":
    main_benchmarks()
