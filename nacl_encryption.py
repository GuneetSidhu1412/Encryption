
import nacl.utils
import nacl.public


def generate_keypair():
    """
    Generates a key pair for encryption using nacl.public.SealedBox.

    Returns:
        tuple: The generated private key and corresponding public key.
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key

    return private_key, public_key


def get_raw_key(nacl_key):
    """
    Returns the underlying 32-byte key value (Curve25519 key) from a nacl.public.PrivateKey
    or nacl.public.PublicKey object.

    Args:
        nacl_key: The nacl key object.

    Returns:
        bytes: The raw key value as bytes.

    Raises:
        TypeError: If the nacl_key is not a PublicKey or PrivateKey object.
    """
    if not (isinstance(nacl_key, nacl.public.PublicKey) or isinstance(nacl_key, nacl.public.PrivateKey)):
        raise TypeError('Expecting a PublicKey or PrivateKey object')

    return nacl_key.encode()


def get_private_key_from_raw_key(key_value):
    """
    Generates a nacl.public.PrivateKey object using a raw key value (32 bytes, a Curve25519 key).

    Args:
        key_value: The raw key value.

    Returns:
        nacl.public.PrivateKey: The nacl private key object.

    Raises:
        TypeError: If the key_value is not of type bytes.
    """
    if not isinstance(key_value, bytes):
        raise TypeError('Arg "key_value" must be of type bytes')

    return nacl.public.PrivateKey(key_value)


def get_public_key_from_raw_key(key_value):
    """
    Generates a nacl.public.PublicKey object using a raw key value (32 bytes, a Curve25519 key).

    Args:
        key_value: The raw key value.

    Returns:
        nacl.public.PublicKey: The nacl public key object.

    Raises:
        TypeError: If the key_value is not of type bytes.
    """
    if not isinstance(key_value, bytes):
        raise TypeError('Arg "key_value" must be of type bytes')

    return nacl.public.PublicKey(key_value)


def encrypt_data(data, public_key):
    """
    Encrypts data using a public key.

    Args:
        data: The data to be encrypted.
        public_key: The public key for encryption.

    Returns:
        bytes: The encrypted data.

    Raises:
        TypeError: If the public_key is not a nacl.public.PublicKey object.
    """
    if not isinstance(public_key, nacl.public.PublicKey):
        raise TypeError('Arg "public_key" must be a nacl.public.PublicKey object')

    encryptor = nacl.public.SealedBox(public_key)
    return encryptor.encrypt(data)


def decrypt_data(encrypted, private_key):
    """
    Decrypts encrypted data using a private key.

    Args:
        encrypted: The encrypted data.
        private_key: The private key for decryption.

    Returns:
        bytes: The decrypted data.

    Raises:
        TypeError: If the private_key is not a nacl.public.PrivateKey object.
    """
    if not isinstance(private_key, nacl.public.PrivateKey):
        raise TypeError('Arg "private_key" must be a nacl.public.PrivateKey object')

    decryptor = nacl.public.SealedBox(private_key)
    return decryptor.decrypt(encrypted)
