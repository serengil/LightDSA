# built-in dependencies
from typing import Optional, Tuple, Union, BinaryIO, cast
import json

# project dependencies
from lightdsa.interfaces.signatures import Signature
from lightdsa.algorithms.eddsa import EdDSA
from lightdsa.algorithms.ecdsa import ECDSA
from lightdsa.algorithms.rsa import RSA
from lightdsa.algorithms.dsa import DSA
from lightdsa.commons.transformation import integerize
from lightdsa.commons.logger import Logger

__version__ = "0.0.1"


logger = Logger(module="lightdsa/__init__.py")


# pylint: disable=eval-used
class LightDSA:
    """
    Build a LightDSA object
    """

    def __init__(
        self,
        algorithm_name: str,
        key_file: Optional[str] = None,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        form_name: Optional[str] = None,
        curve_name: Optional[str] = None,
    ):
        """
        Initialize the LightDSA object
        Args:
            algorithm_name (str): digital signature algorithm name.
                e.g.ECDSA, EdDSA, RSA and DSA.
            key_file (str): pre-built cryptosystem's exported key file.
            keys (dict): pre-built cryptosystem's dictionary keys.
                Considered only if key_file is not provided.
            key_size (int): the key size in bits.
                Considered only if keys and key_file are not provided.
            form_name (str): the elliptic curve form name
                considered if the algorithm_name is ECDSA or EdDSA.
            curve_name (str): the specific elliptic curve name for given form
                considered if the algorithm_name is ECDSA or EdDSA.
        """
        self.algorithm_name = algorithm_name

        if keys is not None and key_file is not None:
            logger.warn(
                "You provided both keys and key_file args."
                "So, key_file will be used, and keys will be ignored."
            )
        if key_file is not None:
            keys = self.__restore_keys(target_file=key_file)

        if algorithm_name is None or algorithm_name.lower() == "eddsa":
            self.dsa = EdDSA(
                form_name=form_name,
                curve_name=curve_name,
                key_size=key_size,
                keys=keys,
            )
        elif algorithm_name.lower() == "ecdsa":
            self.dsa = ECDSA(
                form_name=form_name,
                curve_name=curve_name,
                key_size=key_size,
                keys=keys,
            )
        elif algorithm_name.lower() == "rsa":
            self.dsa = RSA(
                key_size=key_size,
                keys=keys,
            )
        elif algorithm_name.lower() == "dsa":
            self.dsa = DSA(
                key_size=key_size,
                keys=keys,
            )
        else:
            raise ValueError(f"Algorithm {algorithm_name} is not supported")

    def sign(
        self, message: Union[int, str, bytes, BinaryIO]
    ) -> Union[Tuple[int, int], Tuple[Tuple[int, int], int], int]:
        """
        Sign a message
        Args:
            message (Union[int, str, bytes, BinaryIO]): message to be signed
        Returns:
            signature (Union[Tuple[int, int], Tuple[Tuple[int, int], int], int]):
                signature of the message
        """
        if self.dsa.keys.get("private_key") is None:
            raise ValueError("You must have private key to sign a message")

        return self.dsa.sign(integerize(message))

    def verify(
        self,
        message: Union[int, str, bytes, BinaryIO],
        signature: Union[Tuple[int, int], Tuple[Tuple[int, int], int], int],
    ) -> bool:
        """ "
        Verify a message
        Args:
            message (Union[int, str, bytes, BinaryIO]): message to be signed
            signature (Union[Tuple[int, int], Tuple[Tuple[int, int], int], int]): signature of the message
        Returns:
            bool: True if the signature is valid
        """
        if self.dsa.keys.get("public_key") is None:
            raise ValueError("You must have public key to verify a message")

        dsa = cast(Signature, self.dsa)
        return dsa.verify(integerize(message), signature)

    def export_keys(self, target_file: str, public: bool = False) -> None:
        """
        Export keys to a file
        Args:
            target_file (str): target file name
            public (bool): set this to True if you will publish this
                to publicly.
        """
        keys = self.dsa.keys
        private_key = None
        if public is True and keys.get("private_key") is not None:
            private_key = keys["private_key"]
            del keys["private_key"]

        if public is False:
            logger.warn(
                "You did not set public arg to True. So, exported key has private key information."
                "Do not share this to anyone"
            )

        with open(target_file, "w", encoding="UTF-8") as file:
            file.write(json.dumps(keys))

        # restore private key if you dropped
        if private_key is not None:
            self.dsa.keys["private_key"] = private_key

    def __restore_keys(self, target_file: str) -> dict:
        """
        Restore keys from a file
        Args:
            target_file (str): target file name
        Returns:
            keys (dict): private public key pair
        """
        with open(target_file, "r", encoding="UTF-8") as file:
            dict_str = file.read()

        keys = eval(dict_str)
        if not isinstance(keys, dict):
            raise ValueError(
                f"The content of the file {target_file} does not represent a valid dictionary."
            )

        if "private_key" in keys.keys():
            logger.info(f"private-public key pair is restored from {target_file}")
        elif "public_key" in keys.keys():
            logger.info(f"public key is restored from {target_file}")
        else:
            raise ValueError(f"File {target_file} must have public_key key")
        return keys
