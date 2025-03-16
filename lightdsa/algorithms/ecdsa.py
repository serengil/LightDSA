# built-in dependencies
import random
from typing import Optional, Tuple

# 3rd party dependencies
from lightecc import LightECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightdsa.commons import transformation
from lightdsa.interfaces.signatures import Signature
from lightdsa.commons.logger import Logger

logger = Logger(module="lightdsa/algorithms/ecdsa.py")


class ECDSA(Signature):
    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        hash_algorithm: Optional[str] = None,
        form_name: Optional[str] = "weierstrass",
        curve_name: Optional[str] = "secp256k1",
    ):
        """
        Elliptic Curve Digital Signature Algorithm (ECDSA)
        https://sefiks.com/2018/02/16/elegant-signatures-with-elliptic-curve-cryptography/
        """
        self.key_size = key_size
        self.form_name = form_name or "weierstrass"
        self.curve_name = curve_name or "secp256k1"
        self.curve = LightECC(self.form_name, self.curve_name)
        self.keys = keys or self.generate_keys(key_size or self.curve.n.bit_length())
        self.hash_algorithm = hash_algorithm

        self.hash_algorithm = transformation.get_hash_algorithm(self.curve.n)

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate ECDSA keys
        Args:
            key_size (int): size of the key
        Returns:
            dict: private and public
                e.g. keys = {
                    "private_key": {
                        "ka": int
                    },
                    "public_key": {
                        "Qa": Tuple[int, int]
                    }
                }
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        # private key
        ka = random.getrandbits(key_size)
        keys["private_key"]["ka"] = ka

        # public key
        Qa = ka * self.curve.G
        keys["public_key"]["Qa"] = Qa.get_point()

        logger.debug("ECDSA keys generated")

        return keys

    def sign(self, message: int) -> Tuple[int, int]:
        """
        Sign a message with ECDSA
        Args:
            message (int): message to sign
        Returns:
            signature (Tuple[int, int]): signature
        """
        # this must be a random, otherwise private can be extracted from multiple signatures
        random_key = random.getrandbits(self.curve.n.bit_length())
        R = random_key * self.curve.G

        hashed_message = transformation.hashify(message, algorithm=self.hash_algorithm)
        private_key = self.keys["private_key"]["ka"]

        r = R.x
        s = (
            (hashed_message + r * private_key)
            * pow(random_key, -1, self.curve.n)
            % self.curve.n
        )

        return (r, s)

    def verify(self, message: int, signature: Tuple[int, int]) -> bool:
        """
        Verify a message with ECDSA
        Args:
            message (int): message to verify
            signature (Tuple[int, int]): signature
        Returns:
            bool: True if signature is valid, False otherwise
        """
        hashed_message = transformation.hashify(message, algorithm=self.hash_algorithm)

        Qa = self.keys["public_key"]["Qa"]
        public_key = EllipticCurvePoint(Qa[0], Qa[1], self.curve.curve)

        r, s = signature
        w = pow(s, -1, self.curve.n)

        u1 = ((hashed_message * w) % self.curve.n) * self.curve.G
        u2 = ((r * w) % self.curve.n) * public_key

        checkpoint = u1 + u2

        if checkpoint.x != r:
            raise ValueError("Signature is invalid")

        return True
