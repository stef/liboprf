# pyoprf

pyoprf offers Python bindings for the liboprf library, allowing integration of Oblivious Pseudorandom Functions (OPRFs) into Python applications. It provides access to the [features](../README.md#features) of the [liboprf](https://github.com/stef/liboprf) library.

## Installation

### Prerequisites

- [liboprf](https://github.com/stef/liboprf): The core library
- [libsodium](https://github.com/jedisct1/libsodium): Required dependency for liboprf
- OpenSSL: For TLS connections between the participants

### Installing from PyPI

```bash
pip install pyoprf
```

### Installing from source

```bash
git clone https://github.com/stef/liboprf.git
cd liboprf/python
pip install .
```

## Usage

For detailed usage examples, refer to the [`test.py`](./tests/test.py) file and the [`examples`](/examples) folder.

### Basic Example
Imagine a scenario where a client wants to retrieve data from a server using a password, but doesn't want to reveal the actual password to the server:

```python
import pyoprf

# Basic OPRF evaluation process
# Step 1: Client blinds the input value
input_value = b"password123"
blind_factor, blinded_input = pyoprf.blind(input_value)

# Step 2: Server generates a key and evaluates the blinded input
server_key = pyoprf.keygen()
server_evaluation = pyoprf.evaluate(server_key, blinded_input)

# Step 3: Client unblinds the server's response
unblinded_result = pyoprf.unblind(blind_factor, server_evaluation)

# Step 4: Client finalizes the OPRF computation
final_result = pyoprf.finalize(input_value, unblinded_result)

print(f"OPRF result: {final_result.hex()}")

# Verify that repeated evaluations with the same key and input produce the same result
blind_factor2, blinded_input2 = pyoprf.blind(input_value)
server_evaluation2 = pyoprf.evaluate(server_key, blinded_input2)
unblinded_result2 = pyoprf.unblind(blind_factor2, server_evaluation2)
final_result2 = pyoprf.finalize(input_value, unblinded_result2)

print(f"Verification result: {final_result2.hex()}")
assert final_result == final_result2, "OPRF evaluations should be deterministic for the same input and key"

# The `final_result` can be used as a key for encryption, authentication token, and more.
# Only client can derive this value without the server learning the password or the final result.
```

### Threshold Example
Suppose you want to build a password authentication system that distributes trust across multiple servers, so no single server can learn a user's password. The library also supports threshold OPRFs, where multiple servers hold shares of a key:

```python
import pyoprf

# Setting up a threshold OPRF with 3 servers, threshold of 2
# Server setup, which would happen on each server
n = 3  # Total number of servers
t = 2  # The minimum servers needed, also called the threshold

# Generate a key
key = pyoprf.keygen()

# Create shares of the key for distributed evaluation
shares = pyoprf.create_shares(key, n, t)

# On client
input_value = b"password123"
blind_factor, blinded_input = pyoprf.blind(input_value)

# Each server evaluates the input with its share
evaluations = []
for i in range(n):
    # This evaluation happens on server i
    server_evaluation = pyoprf.evaluate(shares[i][1:], blinded_input)
    evaluations.append(shares[i][:1] + server_evaluation)

# Client combines evaluations (need at least t of them)
collected_evaluations = evaluations[:t]  # Just use the first t evaluations
combined = pyoprf.thresholdmult(collected_evaluations)

# Client unblinds the combined result
unblinded = pyoprf.unblind(blind_factor, combined)

# Finalize to get the OPRF output
final_result = pyoprf.finalize(input_value, unblinded)
print(f"Threshold OPRF result: {final_result.hex()}")

# Verify that it matches a direct evaluation with the key
server_evaluation = pyoprf.evaluate(key, blinded_input)
unblinded_direct = pyoprf.unblind(blind_factor, server_evaluation)
direct_result = pyoprf.finalize(input_value, unblinded_direct)
print(f"Direct OPRF result: {direct_result.hex()}")
assert final_result == direct_result, "Threshold evaluation should match direct evaluation"
```

## Troubleshooting

If you encounter issues, first ensure that libsodium, liboprf and OpenSSL are properly installed.

### OpenSSL Header Issues

If after installing OpenSSL, you get the error `'openssl/crypto.h' file not found`, you might need to provide OpenSSL headers to the compiler. For example, if OpenSSL was installed on Mac using Homebrew:
```
export CFLAGS="-I/opt/homebrew/opt/openssl@3/include"
export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
```

### Library Loading Issues

When running Python code, you might encounter errors like:

```
OSError: liboprf.so.0: cannot open shared object file: No such file or directory 
OSError: liboprf-noiseXK.so.0: cannot open shared object file: No such file or directory
```

To fix this, you can try to install liboprf globally on your system.

Either by using your distributions package manager:

```sh
% sudo apt install liboprf0t64
```

Or install liboprf from source:

```sh
cd /path/to/liboprf/src
sudo PREFIX=/usr make install
sudo ldconfig
```

Or by using environment variables, first create symbolic links:

```bash
cd /path/to/liboprf/src
ln -s liboprf.so liboprf.so.0
cd noise_xk
ln -s liboprf-noiseXK.so liboprf-noiseXK.so.0
```

Then when running your Python code, use the LD_LIBRARY_PATH environment variable:

```bash
LD_LIBRARY_PATH=/path/to/liboprf/src:/path/to/liboprf/src/noise_xk python your_script.py
```

## Documentation

For more information on the underlying liboprf functionality, visit the [liboprf documentation](../README.md).

## License

LGPLv3.0+
