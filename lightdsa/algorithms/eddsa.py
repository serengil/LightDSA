# built-in dependencies
import random
from typing import Optional, Tuple

# 3rd party dependencies
from lightecc import LightECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightdsa.interfaces.signatures import Signature
from lightdsa.commons import transformation
from lightdsa.commons.logger import Logger

logger = Logger(module="lightdsa/algorithms/eddsa.py")


class EdDSA(Signature):
    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        form_name: Optional[str] = "edwards",
        curve_name: Optional[str] = "ed25519",
    ):
        """
        Edwards Curve Digital Signature Algorithm (EdDSA)
        https://sefiks.com/2018/12/24/a-gentle-introduction-to-edwards-curve-digital-signature-algorithm-eddsa/
        """
        self.key_size = key_size
        self.form_name = form_name
        self.curve_name = curve_name
        self.curve = LightECC(form_name, curve_name)
        self.keys = keys or self.generate_keys(key_size or self.curve.n.bit_length())
        self.hash_algorithm = transformation.get_hash_algorithm(self.curve.n)

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys for EdDSA
        Args:
            key_size: int
        Returns:
            keys (dict): public and private keys
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

        return keys

    def sign(self, message: int) -> Tuple[Tuple[int, int], int]:
        """
        Sign a message using EdDSA
        Args:
            message: int
        Returns:
            signature (Tuple[Tuple[int, int], int]): signature of the message
        """
        r = transformation.hashify(message, algorithm=self.hash_algorithm) % self.curve.modulo
        R = r * self.curve.G
        h = (R.x + self.keys["public_key"]["Qa"][0] + message) % self.curve.modulo
        s = r + h * self.keys["private_key"]["ka"]
        return (R.get_point(), s)

    def verify(self, message: int, signature: Tuple[Tuple[int, int], int]) -> bool:
        """
        Verify a message using EdDSA
        Args:
            message: int
            signature (Tuple[Tuple[int, int], int]): signature of the message
        Returns:
            bool: True if the signature
        """
        (Rx, Ry), s = signature
        R = EllipticCurvePoint(x=Rx, y=Ry, curve=self.curve.curve)
        public_key = EllipticCurvePoint(
            x=self.keys["public_key"]["Qa"][0],
            y=self.keys["public_key"]["Qa"][1],
            curve=self.curve.curve,
        )
        h = (R.x + self.keys["public_key"]["Qa"][0] + message) % self.curve.modulo
        P1 = s * self.curve.G
        P2 = R + h * public_key

        if P1 != P2:
            raise ValueError("Signature is invalid")

        return True
