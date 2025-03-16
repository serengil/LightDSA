# built-in dependencies
import math
import random
from typing import Optional

# 3rd party dependencies
import sympy

# project dependencies
from lightdsa.interfaces.signatures import Signature
from lightdsa.commons.transformation import hashify
from lightdsa.commons.logger import Logger

logger = Logger(module="lightdsa/algorithms/rsa.py")

DEFAULT_KEY_SIZE = 3072


class RSA(Signature):
    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
    ):
        """
        RSA
        [1] https://sefiks.com/2018/05/21/the-math-behind-rsa-algorithm/
        [2] https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/
        """
        self.key_size = key_size
        self.keys = keys or self.generate_keys(key_size or DEFAULT_KEY_SIZE)

        if key_size is None or key_size < 3072:
            self.hash_algorithm = "sha256"
        elif key_size < 4096:
            self.hash_algorithm = "sha384"
        else:
            self.hash_algorithm = "sha512"

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of RSA cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
                e.g. keys = {
                    "private_key": {
                        "d": int
                    },
                    "public_key": {
                        "n": int,
                        "e": int
                    }
                }
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        while True:
            try:
                # picking a prime modulus p and q
                p = sympy.randprime(200, 2 ** int(key_size / 2) - 1)
                q = sympy.randprime(200, 2 ** int(key_size / 2) - 1)

                assert isinstance(p, int)
                assert isinstance(q, int)

                n = p * q
                phi = (p - 1) * (q - 1)

                # select public exponent e
                while True:
                    e = random.randint(1, phi - 1)
                    if math.gcd(e, n) == 1:
                        break

                d = pow(e, -1, phi)
                break
            except:
                pass

        keys["public_key"]["n"] = n
        keys["public_key"]["e"] = e
        keys["private_key"]["d"] = d
        return keys

    def sign(self, message: int) -> int:
        """
        Sign a message with RSA
        Args:
            message (int): message to sign
        Returns:
            signature (int): signature
        """
        n = self.keys["public_key"]["n"]

        hashed_message = hashify(message, algorithm=self.hash_algorithm)

        d = self.keys["private_key"]["d"]
        c = pow(hashed_message, d, n)

        return c

    def verify(self, message: int, signature: int) -> bool:
        """
        Verify a message with RSA
        Args:
            message (int): message to verify
            signature (int): signature
        Returns:
            bool: True if signature is valid, False otherwise
        """
        n = self.keys["public_key"]["n"]
        e = self.keys["public_key"]["e"]
        hashed_message_prime = pow(signature, e, n)
        hashed_message = hashify(message, algorithm=self.hash_algorithm)

        if hashed_message_prime != hashed_message:
            raise ValueError("Signature is invalid")

        return True
