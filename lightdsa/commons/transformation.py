# built-in dependencies
import hashlib
from typing import Optional, Union, BinaryIO

# pylint: disable=no-else-return


def integerize(message: Union[int, str, bytes, BinaryIO]) -> int:
    """
    Integerize a message
    Args:
        message (Union[int, str, bytes, BinaryIO, TextIO]): message to integerize
    Returns:
        int: integerized message
    """
    if isinstance(message, int):
        return message
    elif isinstance(message, str):
        message_bytes = message.encode("utf-8")
        message_hex = message_bytes.hex()
        return int(message_hex, 16)
    elif isinstance(message, bytes):
        message_hex = message.hex()
        return int(message_hex, 16)
    elif isinstance(message, (BinaryIO)):
        return int(message.read().strip())  # Read file content and convert
    else:
        raise ValueError("Unsupported type")


def hashify(m: int, algorithm: Optional[str] = "sha256") -> int:
    """
    Hash an integer using a specified algorithm
    Args:
        m (int): integer to hash
        algorithm (str): hashing algorithm
    Returns:
        hash_message (int): hashed integer
    """
    hash_functions = {
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }

    if algorithm not in hash_functions:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    return int(hash_functions[algorithm](str(m).encode("utf-8")).hexdigest(), 16)


def get_hash_algorithm(n: int) -> str:
    """
    Get hash algorithm based on the bit length of ellitpic curve order
    Args:
        n (int): Elliptic curve order
    Returns:
        algorithm (str): hash algorithm
    """
    hash_algorithms = {
        range(0, 160): "sha1",
        range(160, 224): "sha224",
        range(224, 256): "sha256",
        range(256, 384): "sha384",
        range(384, 100000): "sha512",
    }
    hash_algorithm = "sha256"
    for bit_range, algorithm in hash_algorithms.items():
        if n.bit_length() in bit_range:
            hash_algorithm = algorithm
            break
    return hash_algorithm
