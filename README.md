# Cryptographic Operations Utility

This Python module provides a set of functions for cryptographic operations using the `nacl` library. It serves as a versatile tool for generating key pairs, extracting raw key values, encrypting data with a public key, and decrypting data with a private key.

## Functions

### `generate_key_pair()`

Generates a key pair for encryption using `nacl.public.SealedBox`.

**Returns:**
- **Tuple:** The generated private key and corresponding public key.

### `get_raw_key(nacl_key)`

Returns the underlying 32-byte key value (Curve25519 key) from a `nacl.public.PrivateKey` or `nacl.public.PublicKey` object.

**Parameters:**
- `nacl_key`: The nacl key object.

**Returns:**
- **Bytes:** The raw key value as bytes.

**Raises:**
- **TypeError:** If the `nacl_key` is not a `PublicKey` or `PrivateKey` object.

### `get_private_key_from_raw_key(key_value)`

Generates a `nacl.public.PrivateKey` object using a raw key value (32 bytes, a Curve25519 key).

**Parameters:**
- `key_value`: The raw key value.

**Returns:**
- **nacl.public.PrivateKey:** The nacl private key object.

**Raises:**
- **TypeError:** If the `key_value` is not of type bytes.

### `get_public_key_from_raw_key(key_value)`

Generates a `nacl.public.PublicKey` object using a raw key value (32 bytes, a Curve25519 key).

**Parameters:**
- `key_value`: The raw key value.

**Returns:**
- **nacl.public.PublicKey:** The nacl public key object.

**Raises:**
- **TypeError:** If the `key_value` is not of type bytes.

### `encrypt_data(data, public_key)`

Encrypts data using a public key.

**Parameters:**
- `data`: The data to be encrypted.
- `public_key`: The public key for encryption.

**Returns:**
- **Bytes:** The encrypted data.

**Raises:**
- **TypeError:** If the `public_key` is not a `nacl.public.PublicKey` object.

### `decrypt_data(encrypted, private_key)`

Decrypts encrypted data using a private key.

**Parameters:**
- `encrypted`: The encrypted data.
- `private_key`: The private key for decryption.

**Returns:**
- **Bytes:** The decrypted data.

**Raises:**
- **TypeError:** If the `private_key` is not a `nacl.public.PrivateKey` object.
