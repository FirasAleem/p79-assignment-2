import time
import statistics
import os
import base64

from spake.spake import SPAKE2Party, SpakeHandshake, SecureChannel

# Alias for base64 encoding/decoding
b64e = base64.b64encode
b64d = base64.b64decode

def benchmark_spake2_handshake(num_iter: int = 100, warmup: int = 10) -> None:
    """
    Benchmark the SPAKE2 handshake over num_iter iterations,
    with a warm-up phase of 'warmup' iterations.
    Measures total handshake time and prints average, median, standard deviation,
    min, and max durations.
    """
    password = b"benchmark_password"

    # Warm-up phase
    for _ in range(warmup):
        alice = SPAKE2Party("Alice", password, use_m=True)
        bob = SPAKE2Party("Bob", password, use_m=False)
        handshake = SpakeHandshake(alice, bob)
        _ = handshake.run_handshake()

    durations = []
    for _ in range(num_iter):
        alice = SPAKE2Party("Alice", password, use_m=True)
        bob = SPAKE2Party("Bob", password, use_m=False)
        handshake = SpakeHandshake(alice, bob)

        start = time.perf_counter()
        _ = handshake.run_handshake()
        end = time.perf_counter()

        durations.append(end - start)

    avg_time = statistics.mean(durations)
    median_time = statistics.median(durations)
    stdev_time = statistics.stdev(durations) if len(durations) > 1 else 0
    min_time = min(durations)
    max_time = max(durations)

    print(f"SPAKE2 handshake benchmark over {num_iter} iterations:")
    print(f"  Average time: {avg_time:.6f} sec")
    print(f"  Median time:  {median_time:.6f} sec")
    print(f"  Std deviation: {stdev_time:.6f} sec")
    print(f"  Min time:     {min_time:.6f} sec, Max time: {max_time:.6f} sec")


def benchmark_secure_channel(num_iter: int = 1000, warmup: int = 100) -> None:
    """
    Benchmark the SPAKE2 secure channel round-trip (encryption + decryption)
    over num_iter iterations, with warmup iterations.
    Reports average, median, standard deviation, min, and max durations.
    """
    session_key = os.urandom(32)
    mac_key = os.urandom(32)
    channel = SecureChannel(session_key, mac_key)
    message = b"Benchmark test message for secure channel."

    # Warm-up phase
    for _ in range(warmup):
        encrypted = channel.send_message(message)
        _ = channel.receive_message(encrypted)

    durations = []
    for _ in range(num_iter):
        start = time.perf_counter()
        encrypted = channel.send_message(message)
        decrypted = channel.receive_message(encrypted)
        end = time.perf_counter()

        assert decrypted == message  # Ensure correctness
        durations.append(end - start)

    avg_time = statistics.mean(durations)
    median_time = statistics.median(durations)
    stdev_time = statistics.stdev(durations) if len(durations) > 1 else 0
    min_time = min(durations)
    max_time = max(durations)

    print(f"SPAKE2 secure channel benchmark over {num_iter} iterations:")
    print(f"  Average time: {avg_time:.6f} sec")
    print(f"  Median time:  {median_time:.6f} sec")
    print(f"  Std deviation: {stdev_time:.6f} sec")
    print(f"  Min time:     {min_time:.6f} sec, Max time: {max_time:.6f} sec")


def benchmark_message_size_effect():
    """
    Benchmark encryption and decryption with different message sizes.
    """
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

def benchmark_secure_channel_overhead():
    """Measure message expansion due to encryption and authentication."""
    session_key = os.urandom(32)
    mac_key = os.urandom(32)
    channel = SecureChannel(session_key, mac_key)

    message_sizes = [16, 64, 256, 1024, 4096, 16384]  # Various message sizes
    print("\nSecure Channel Message Expansion:")

    for size in message_sizes:
        message = os.urandom(size)
        encrypted = channel.send_message(message)
        expansion_ratio = len(encrypted) / len(message)

        print(f"  Plaintext: {size} bytes -> Encrypted: {len(encrypted)} bytes (x{expansion_ratio:.2f})")

def main_benchmarks():
    print("Running SPAKE2 handshake benchmark...")
    benchmark_spake2_handshake(num_iter=100, warmup=5)

    print("\nRunning SPAKE2 secure channel benchmark...")
    benchmark_secure_channel(num_iter=1000, warmup=50)

    print("\nBenchmarking effect of message size on encryption/decryption...")
    benchmark_message_size_effect()

    print("\nBenchmarking secure channel message expansion...")
    benchmark_secure_channel_overhead()

if __name__ == "__main__":
    main_benchmarks()