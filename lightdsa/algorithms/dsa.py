# built-in dependencies
import random
from typing import Optional, Tuple

# 3rd party dependencies
import sympy

# project dependencies
from lightdsa.interfaces.signatures import Signature
from lightdsa.commons.transformation import hashify
from lightdsa.commons.logger import Logger

logger = Logger(module="lightdsa/algorithms/dsa.py")

DEFAULT_KEY_SIZE = 30


class DSA(Signature):
    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
    ):
        """
        DSA
        https://sefiks.com/2023/06/14/digital-signature-algorithm-dsa-in-python-from-scratch
        """
        self.key_size = key_size
        self.keys = keys or self.generate_keys(key_size or DEFAULT_KEY_SIZE)

        if key_size is None or key_size < 3072:
            self.hash_algorithm = "sha256"
        elif key_size < 4096:
            self.hash_algorithm = "sha384"
        else:
            self.hash_algorithm = "sha512"

        logger.warn(
            "DSA in LightDSA is experimental purposes and not recommended for production use."
            "Because its key generation time is too long for required key sizes."
            "That is why, we generated a DSA cryptosystem with small key size."
        )

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of RSA cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        q = sympy.randprime(2 ** (key_size // 2 - 1), 2 ** (key_size // 2))
        # Generate p such that (p - 1) % q == 0
        while True:
            p = sympy.randprime(2 ** (key_size - 1), 2**key_size)
            if (p - 1) % q == 0:
                break

        logger.debug(f"{p=}, {q=} just generated")

        a = int((p - 1) // q)

        while True:
            h = random.randint(2, p - 2)
            g = pow(h, a, p)

            if g > 1 and pow(g, q, p) == 1:
                break

        logger.debug(f"{g=}, {h=}")

        # private key
        x = random.randint(1, q - 1)

        # public key
        y = pow(g, x, p)

        # public arguments: p, q, a, g

        keys["private_key"]["x"] = x
        keys["public_key"]["y"] = y
        keys["public_key"]["p"] = p
        keys["public_key"]["q"] = q
        keys["public_key"]["a"] = a
        keys["public_key"]["g"] = g

        return keys

    def sign(self, message: int) -> Tuple[int, int]:
        """
        Sign a message with RSA
        Args:
            message (int): message to sign
        Returns:
            signature (int): signature
        """
        x = self.keys["private_key"]["x"]
        q = self.keys["public_key"]["q"]
        g = self.keys["public_key"]["g"]
        p = self.keys["public_key"]["p"]

        while True:
            k = random.randint(1, q - 1)
            r = pow(g, k, p) % q

            hashed_message = hashify(message, algorithm=self.hash_algorithm)

            s = (pow(k, -1, q) * (hashed_message + x * r)) % q

            if r != 0 and s != 0:
                break

        return r, s

    def verify(self, message: int, signature: Tuple[int, int]) -> bool:
        """
        Verify a message with RSA
        Args:
            message (int): message to verify
            signature (int): signature
        Returns:
            bool: True if signature is valid, False otherwise
        """
        hashed_message = hashify(message, algorithm=self.hash_algorithm)

        r, s = signature

        # restore public key and configuration
        q = self.keys["public_key"]["q"]
        g = self.keys["public_key"]["g"]
        p = self.keys["public_key"]["p"]
        y = self.keys["public_key"]["y"]

        w = pow(s, -1, q)
        u1 = (hashed_message * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

        if v != r:
            raise ValueError("Invalid signature")

        return True
