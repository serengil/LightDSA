# built-in dependencies
import os

# 3rd party dependencies
import pytest

# project dependencies
from lightdsa import LightDSA
from lightdsa.commons.logger import Logger

logger = Logger(module="tests/test_types.py")

ALGORITHMS = ["EdDSA", "ECDSA", "RSA"]


@pytest.mark.parametrize(
    "algorithm_name",
    ALGORITHMS,
)
def test_string_input(algorithm_name):
    dsa = LightDSA(algorithm_name=algorithm_name)

    m = "Hello, world!"
    signature = dsa.sign(m)

    assert dsa.verify(m, signature) is True
    logger.info(f"✅ string input test succeeded for {algorithm_name}")


@pytest.mark.parametrize(
    "algorithm_name",
    ALGORITHMS,
)
def test_file_input(algorithm_name):
    m = "Hello, world!"

    if os.path.exists("/tmp/message.txt") is False:
        with open("/tmp/message.txt", "w", encoding="utf-8") as f:
            f.write(m)

    with open("/tmp/message.txt", "rb") as file:
        message_bytes = file.read()

    assert isinstance(message_bytes, bytes)

    dsa = LightDSA(algorithm_name=algorithm_name)
    signature = dsa.sign(message_bytes)

    assert dsa.verify(message_bytes, signature) is True

    logger.info(f"✅ file input test succeeded for {algorithm_name}")
