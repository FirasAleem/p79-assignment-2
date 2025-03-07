import timeit
import statistics
import os
import cProfile
import pstats
from spake2.spake2 import SPAKE2Party, SPAKE2Handshake, SecureChannel 
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Ensure output directory exists
OUTPUT_DIR = "benchmarking/profiling_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Global password for SPAKE2 benchmarking
PASSWORD = b"securepassword"

def print_results(name, times, num_iter):
    """
    Prints benchmarking results including mean, median, p90, and p99 latencies.
    Reports time per single operation.
    """
    avg_time = statistics.mean(times) / num_iter  
    median_time = statistics.median(times) / num_iter  
    stdev_time = statistics.stdev(times) / num_iter if len(times) > 1 else 0
    min_time = min(times) / num_iter  
    max_time = max(times) / num_iter  
    p90 = statistics.quantiles(times, n=10)[8] / num_iter  
    p99 = statistics.quantiles(times, n=100)[98] / num_iter  

    print(f"{name} benchmark over {num_iter} iterations:")
    print(f"  Average time per operation: {avg_time:.9f} sec")
    print(f"  Median time per operation:  {median_time:.9f} sec")
    print(f"  Std deviation per operation: {stdev_time:.9f} sec")
    print(f"  Min time per operation:     {min_time:.9f} sec, Max time per operation: {max_time:.9f} sec")
    print(f"  P90 latency per operation:  {p90:.9f} sec, P99 latency per operation: {p99:.9f} sec\n")

def profile_function(func, output_file):
    profile_path = os.path.join(OUTPUT_DIR, f"{output_file}.prof")
    txt_output_path = os.path.join(OUTPUT_DIR, f"{output_file}.txt")

    with cProfile.Profile() as pr:
        func()  

    # Save profiling stats
    pr.dump_stats(profile_path)

    # Save readable output
    with open(txt_output_path, "w") as f:
        stats = pstats.Stats(pr, stream=f)
        stats.strip_dirs().sort_stats("cumulative").print_stats(15)

    print(f"Profiling results saved: {profile_path} & {txt_output_path}")

def setup_SPAKE2():
    alice = SPAKE2Party("Alice", PASSWORD, use_m=True)
    bob = SPAKE2Party("Bob", PASSWORD, use_m=False)
    return SPAKE2Handshake(alice, bob)

def run_SPAKE2_handshake():
    handshake = setup_SPAKE2()
    return handshake.run_handshake()


def benchmark_SPAKE2_handshake(num_iter=100, warmup=10):
    """
    Benchmarks the SPAKE2 handshake execution time.
    """
    # Warm-up phase
    for _ in range(warmup):
        run_SPAKE2_handshake()

    # Benchmarking
    times = timeit.repeat(run_SPAKE2_handshake, repeat=5, number=num_iter)
    print_results("SPAKE2 Handshake", times, num_iter)

def benchmark_SPAKE2_key_exchange(num_iter=1000):
    """
    Benchmarks SPAKE2 key exchange (shared secret computation).
    """
    alice = SPAKE2Party("Alice", PASSWORD, use_m=True)
    bob = SPAKE2Party("Bob", PASSWORD, use_m=False)
    alice.receive_peer_message(bob.pi, "Bob")

    times = timeit.repeat(lambda: alice.compute_shared_secret(), repeat=5, number=num_iter)
    print_results("SPAKE2 Key Exchange", times, num_iter)

def setup_secure_channel():
    """
    Sets up a SecureChannel by deriving keys from the SPAKE2 handshake.
    """
    handshake = setup_SPAKE2()
    shared_secret, _ = handshake.run_handshake()

    # Derive session & MAC keys
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"SecureChannel")
    derived_keys = kdf.derive(shared_secret)
    session_key = derived_keys

    return SecureChannel(session_key)

def benchmark_secure_channel(num_iter=1000, warmup=100):
    """
    Benchmarks SecureChannel encryption and decryption.
    """
    channel = setup_secure_channel()
    message = b"Performance test message for secure channel."

    # Warm-up phase
    for _ in range(warmup):
        encrypted = channel.send_message(message)
        _ = channel.receive_message(encrypted)

    times = timeit.repeat(lambda: channel.receive_message(channel.send_message(message)), repeat=5, number=num_iter)
    print_results("Secure Channel (AES-GCM Encryption + HMAC)", times, num_iter)

def main_benchmarks():
    print("\nRunning SPAKE2 handshake benchmark...")
    benchmark_SPAKE2_handshake(num_iter=100, warmup=5)

    print("\nRunning SPAKE2 key exchange benchmark...")
    benchmark_SPAKE2_key_exchange(num_iter=1000)

    print("\nRunning Secure Channel benchmark (encryption and decryption)...")
    benchmark_secure_channel(num_iter=1000, warmup=50)

    # Profiling
    print("\nProfiling SPAKE2 handshake...")
    profile_function(run_SPAKE2_handshake, "SPAKE2_handshake")

if __name__ == "__main__":
    main_benchmarks()
