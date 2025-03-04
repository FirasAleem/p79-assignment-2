# X25519 & Ed25519 Implementation

This project provides an implementation of X25519 for key exchange and Ed25519 for digital signatures, following **RFC 7748** and **RFC 8032**.

## Features

- **X25519 Key Exchange**: Secure elliptic-curve Diffie-Hellman (ECDH) using Curve25519.
- **Ed25519 Digital Signatures**: High-performance signing and verification.
- **Batch Verification**: Efficiently verify multiple Ed25519 signatures.
- **Docker Support**: Run the project in a containerized environment.

## Project Structure

```
project_root/
│── ed25519/
│   ├── ed25519.py
│   ├── utils.py
│── x25519/
│   ├── x25519.py
│   ├── utils.py
│   ├── montgomery_ladder.py
│   ├── montgomery_double_add.py
│── tests/
│   ├── test_ed25519.py
│   ├── test_montgomery_double_add.py
│   ├── test_montgomery_ladder.py
│   ├── test_x25519_ecdh.py
│   ├── test_x25519_utils.py
│   ├── test_x25519.py
│── requirements.txt
│── README.md
│── Dockerfile
│── run_tests.sh
│── run.sh
│── .gitignore
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
from x25519 import X25519

x25519 = X25519()
private_key = x25519.generate_private_key()
public_key = x25519.generate_public_key(private_key)

# Perform ECDH key exchange
shared_secret = x25519.scalar_multiply(private_key, public_key)
```

### Ed25519 Signing and Verification
```python
from ed25519 import Ed25519

ed25519 = Ed25519()
private_key = ed25519.generate_private_key()
public_key = ed25519.generate_public_key(private_key)

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

## Testing

Run unit tests to verify correctness:

```bash
./run_tests.sh
```

Or manually run tests:

```bash
python3 -m unittest discover -v -s tests
```

## Compliance

- **X25519** follows **RFC 7748**.
- **Ed25519** follows **RFC 8032**.
- **Batch verification** is implemented based on **Algorithm 3 from**  
[  *Taming the Many EdDSAs*](https://link.springer.com/chapter/10.1007/978-3-030-64357-7_4#Tab6) (Hülsing et al., 2021).  

