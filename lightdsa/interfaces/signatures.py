# built-in dependencies
from typing import Tuple, Union
from abc import ABC, abstractmethod

class Signature(ABC):
    @abstractmethod
    def generate_keys(self, key_size: int) -> dict:
        pass

    @abstractmethod
    def sign(self, message: int) -> Union[Tuple[Tuple[int, int], int], Tuple[int, int], int]:
        pass

    @abstractmethod
    def verify(self, message: int, signature: Union[Tuple[Tuple[int, int], int], Tuple[int, int], int]) -> bool:
        pass
