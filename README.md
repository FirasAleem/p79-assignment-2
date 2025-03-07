# X25519, Ed25519, SPAKE2 & SIGMA Implementation

This project implements **X25519** for key exchange, **Ed25519** for digital signatures, **SIGMA** for authenticated key exchange, and **SPAKE2** for password-authenticated key exchange, following relevant **RFCs**.

## Features

- **X25519 Key Exchange**: Secure elliptic-curve Diffie-Hellman (ECDH) using Curve25519 (**RFC 7748**).
- **Ed25519 Digital Signatures**: High-performance signing and verification (**RFC 8032**).
- **Batch Verification**: Efficiently verify multiple Ed25519 signatures.
- **SIGMA Protocol**: Authenticated key exchange for secure session establishment, implementing both a normal version (SIGMA) and an identity & signature protection version (SIGMA-I).
- **SPAKE2 Protocol**: Password-authenticated key exchange (**RFC 9382**).
- **Docker Support**: Run the project in a containerized environment.

## Project Structure
```
project_root/
├── ed25519/
│   ├── ed25519.py
│   ├── utils.py
├── x25519/
│   ├── x25519.py
│   ├── utils.py
│   ├── montgomery_ladder.py
│   ├── montgomery_double_add.py
├── sigma/
│   ├── sigma.py
├── spake2/
│   ├── spake2.py
├── tests_ass1/
│   ├── test_ed25519.py
│   ├── test_montgomery_double_add.py
│   ├── test_montgomery_ladder.py
│   ├── test_x25519_ecdh.py
│   ├── test_x25519_utils.py
│   ├── test_x25519.py
├── tests/
│   ├── test_spake2.py
│   ├── test_sigma.py
├── benchmarking/
│   ├── benchmark_sigma.py
│   ├── benchmark_spake2.py
├── requirements.txt
├── README.md
├── Dockerfile
├── run_tests.sh
├── run.sh
```

## Installation

### Option 1: Run Locally

1. Install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Run the tests:
   ```bash
   ./run_tests.sh
   ```

### Option 2: Run with Docker

Build and run the container:
```bash
./run.sh
```

## Usage

### X25519 Key Exchange
```python
from x25519 import X25519PrivateKey, X25519PublicKey

private_key = X25519PrivateKey.generate()
public_key = X25519PublicKey.from_private_key(private_key)

# Perform ECDH key exchange
shared_secret = private_key.exchange(public_key)
```

### Ed25519 Signing and Verification
```python
from ed25519 import SigningKey, VerifyingKey

private_key = SigningKey.generate()
public_key = SigningKey.generate_verifying_key(private_key)

message = b"Hello, world!"
signature = ed25519.sign(private_key, message)

# Verify the signature
assert ed25519.verify(public_key, message, signature)
```

### Batch Verification (Ed25519)
```python
batch = [
    (public_key1, message1, signature1),
    (public_key2, message2, signature2),
    # More signatures...
]

valid = ed25519.verify_batch(batch)
assert valid
```

### SIGMA Authenticated Key Exchange
```python
from sigma.sigma import SigmaParty, SigmaHandshake, SecureChannel
from sigma.certificates import CertificateAuthority, Certificate

# Step 1: Setup CA and create parties
ca = CertificateAuthority("TestCA")
alice = SigmaParty("Alice", ca.public_key)
bob = SigmaParty("Bob", ca.public_key)

# Issue and assign certificates
alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

# Step 2: Perform SIGMA handshake
handshake = SigmaHandshake(alice, bob, identity_protection=False)
sigma_init_msg = handshake.create_initiation_message()
sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
session_key = handshake.finalize_handshake(sigma_final_msg)

# Step 3: Secure messaging using AES-GCM
secure_channel_alice = SecureChannel(alice.session_key)
secure_channel_bob = SecureChannel(bob.session_key)

# Alice sends an encrypted message to Bob
plaintext = b"Hello Bob, this is a secret message from Alice!"
encrypted_message = secure_channel_alice.send_message(plaintext)

# Bob decrypts it
decrypted_message = secure_channel_bob.receive_message(encrypted_message)
print("\nDecrypted message at Bob:", decrypted_message.decode())
```

In order to use the identity and signature protection version (SIGMA-I), simply set `identity_protection=True`. All other steps remain the same. 

```python
# Perform handshake with identity protection enabled
handshake = SigmaHandshake(alice, bob, identity_protection=True)
```

### SPAKE2 Password-Authenticated Key Exchange 
```python
from spake2.spake2 import SPAKE2Party, SPAKE2Handshake

password = b"securepassword"

alice = SPAKE2Party("Alice", password, use_m=True)
bob = SPAKE2Party("Bob", password, use_m=False)

handshake = SPAKE2Handshake(alice, bob)
shared_secret, transcript = handshake.run_handshake()

print("Shared Secret:", shared_secret.hex())
```

## Testing

Run unit tests to verify correctness:

```bash
./run_tests.sh
```

Or manually run tests:

```bash
python3 -m pytest tests/
```

### Performance Benchmarking

To measure the performance of the implemented protocols, you can use the provided benchmarking scripts.

#### SIGMA Protocol

To benchmark the SIGMA protocol, run the following command:

```bash
python3 benchmarking/benchmark_sigma.py
```

This script performs multiple iterations of the SIGMA handshake, measuring the execution time for each iteration. It then calculates and reports the average time taken per run, providing insights into the protocol's performance.

#### SPAKE2 Protocol

To benchmark the SPAKE2 protocol, run the following command:

```bash
python3 benchmarking/benchmark_spake2.py
```

Similar to the SIGMA benchmarking script, this script executes multiple iterations of the SPAKE2 handshake, records the execution times, and reports the average time per run. This helps in evaluating the efficiency of the SPAKE2 implementation.

Additionally, the benchmarking scripts also generate profiling information, which is saved to text files for further analysis. This profiling data includes detailed insights into the performance characteristics of the protocol implementations, helping to identify potential bottlenecks and areas for optimization.

## Compliance

- **X25519** follows **RFC 7748**.
- **Ed25519** follows **RFC 8032**.
- **Batch verification** is implemented based on **Algorithm 3 from**  [  *Taming the Many EdDSAs*](https://link.springer.com/chapter/10.1007/978-3-030-64357-7_4#Tab6) (Hülsing et al., 2021).  
- **SIGMA** is implemented based on the protocol from **Section 5.1** from [*SIGMA: The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols*](https://dx.doi.org/10.1007/978-3-540-45146-4_24) (Krawczyk, 2003).
- **SPAKE2** follows **RFC 9382**