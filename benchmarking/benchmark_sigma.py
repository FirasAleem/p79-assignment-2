import timeit
import statistics
import os
import cProfile
import pstats

from sigma.sigma import CertificateAuthority, SigmaParty, SigmaHandshake, SecureChannel
from ed25519.ed25519 import SigningKey, VerifyingKey
from x25519.x25519 import X25519PrivateKey, X25519PublicKey

# Ensure output directory exists
OUTPUT_DIR = "benchmarking/profiling_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Print benchmark results
def print_results(name, times, num_iter):
    """
    Prints benchmarking results including mean, median, p90, and p99 latencies.
    Now reports time per single operation.
    """
    avg_time = statistics.mean(times) / num_iter  
    median_time = statistics.median(times) / num_iter  
    stdev_time = (statistics.stdev(times) / num_iter) if len(times) > 1 else 0
    min_time = min(times) / num_iter  
    max_time = max(times) / num_iter  
    p90 = (statistics.quantiles(times, n=10)[8]) / num_iter  
    p99 = (statistics.quantiles(times, n=100)[98]) / num_iter  

    print(f"{name} benchmark over {num_iter} iterations:")
    print(f"  Average time per operation: {avg_time:.9f} sec")
    print(f"  Median time per operation:  {median_time:.9f} sec")
    print(f"  Std deviation per operation: {stdev_time:.9f} sec")
    print(f"  Min time per operation:     {min_time:.9f} sec, Max time per operation: {max_time:.9f} sec")
    print(f"  P90 latency per operation:  {p90:.9f} sec, P99 latency per operation: {p99:.9f} sec\n")

# Setup and run SIGMA handshake
def setup_sigma_handshake(ca_public_key, identity_protection=False):
    alice = SigmaParty("Alice", ca_public_key)
    bob = SigmaParty("Bob", ca_public_key)
    ca = CertificateAuthority("BenchmarkCA")

    alice_cert = ca.issue_certificate("Alice", alice.ed25519_public)
    bob_cert = ca.issue_certificate("Bob", bob.ed25519_public)

    alice.set_certificate(alice_cert)
    bob.set_certificate(bob_cert)

    return SigmaHandshake(alice, bob, identity_protection)

def run_handshake(handshake):
    sigma_init_msg = handshake.create_initiation_message()
    sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
    sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
    return handshake.finalize_handshake(sigma_final_msg)


# Profiling function, saves results to file
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

# Benchmark functions

def benchmark_sigma_handshake(num_iter=100, warmup=10, identity_protection=False):
    ca = CertificateAuthority("BenchmarkCA")
    ca_public_key = ca.public_key

    # Warm-up phase
    for _ in range(warmup):
        handshake = setup_sigma_handshake(ca_public_key, identity_protection)
        run_handshake(handshake)

    # Benchmark with many iterations
    times = timeit.repeat(
        lambda: run_handshake(setup_sigma_handshake(ca_public_key, identity_protection)),
        repeat=5,
        number=num_iter
    )
    print(times)

    label = f"SIGMA{'-I' if identity_protection else ''} Handshake"
    print_results(label, times, num_iter)

def benchmark_secure_channel(num_iter=1000, warmup=100):
    session_key = os.urandom(32)
    mac_key = os.urandom(32)
    channel = SecureChannel(session_key)
    message = b"Performance test message for secure channel."

    for _ in range(warmup):
        encrypted = channel.send_message(message)
        _ = channel.receive_message(encrypted)

    times = timeit.repeat(
        lambda: channel.receive_message(channel.send_message(message)),
        repeat=5,
        number=num_iter
    )

    print_results("Secure Channel (AES-GCM Encryption + HMAC)", times, num_iter)

def benchmark_signature(num_iter=10000):
    sk = SigningKey.generate()
    vk = VerifyingKey.from_signing_key(sk)
    message = b"Benchmarking Ed25519 signatures"

    times_sign = timeit.repeat(lambda: sk.sign(message), repeat=5, number=num_iter)
    signature = sk.sign(message)
    times_verify = timeit.repeat(lambda: vk.verify(message, signature), repeat=5, number=num_iter)

    print_results("Ed25519 Signing", times_sign, num_iter)
    print_results("Ed25519 Verification", times_verify, num_iter)

def benchmark_key_exchange(num_iter=10000):
    priv1 = X25519PrivateKey.generate()
    priv2 = X25519PrivateKey.generate()
    pub2 = X25519PublicKey.from_private_key(priv2)

    times = timeit.repeat(lambda: priv1.exchange(pub2), repeat=5, number=num_iter)
    print_results("X25519 Key Exchange", times, num_iter)

def benchmark_message_size_effect():
    session_key = os.urandom(32)
    channel = SecureChannel(session_key)
    small_msg, large_msg = b"A" * 64, b"A" * 1024 * 1024  # 1MB

    times_small = timeit.repeat(lambda: channel.receive_message(channel.send_message(small_msg)), repeat=5, number=1000)
    times_large = timeit.repeat(lambda: channel.receive_message(channel.send_message(large_msg)), repeat=5, number=100)

    print_results("AES-GCM Encryption+Decryption (64 bytes)", times_small, 1000)
    print_results("AES-GCM Encryption+Decryption (1MB)", times_large, 100)

def main_benchmarks():
    print("\nRunning SIGMA handshake benchmark...")
    benchmark_sigma_handshake(num_iter=100, warmup=5, identity_protection=False)

    print("\nRunning SIGMA-I handshake benchmark...")
    benchmark_sigma_handshake(num_iter=100, warmup=5, identity_protection=True)

    print("\nRunning secure channel benchmark...")
    benchmark_secure_channel(num_iter=1000, warmup=50)

    print("\nRunning Ed25519 signature benchmark...")
    benchmark_signature(num_iter=1000)

    print("\nRunning X25519 key exchange benchmark...")
    benchmark_key_exchange(num_iter=1000)

    print("\nBenchmarking message size effect...")
    benchmark_message_size_effect()

    # Profiling
    print("\nProfiling SIGMA handshake...")
    profile_function(lambda: run_handshake(setup_sigma_handshake(CertificateAuthority("BenchmarkCA").public_key)), "sigma_handshake")

    print("\nProfiling SIGMA-I handshake...")
    profile_function(lambda: run_handshake(setup_sigma_handshake(CertificateAuthority("BenchmarkCA").public_key, identity_protection=True)), "sigma_i_handshake")

    print("\nProfiling Secure Channel (AES-GCM)...")
    profile_function(lambda: SecureChannel(os.urandom(32)).send_message(b"Test"), "secure_channel")

    print("\nProfiling Ed25519 Signing...")
    profile_function(lambda: SigningKey.generate().sign(b"Benchmarking Ed25519 signing"), "ed25519_signing")

    print("\nProfiling Ed25519 Verification...")
    profile_function(lambda: VerifyingKey.from_signing_key(SigningKey.generate()).verify(b"Benchmarking", SigningKey.generate().sign(b"Benchmarking")), "ed25519_verification")

    print("\nProfiling X25519 Key Exchange...")
    profile_function(lambda: X25519PrivateKey.generate().exchange(X25519PublicKey.from_private_key(X25519PrivateKey.generate())), "x25519_key_exchange")

if __name__ == "__main__":
    main_benchmarks()
