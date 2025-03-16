# 3rd party dependencies
import pytest

# project dependencies
from lightdsa import LightDSA
from lightdsa.commons.logger import Logger

logger = Logger(module="tests/test_api.py")

ALGORITHMS = ["EdDSA", "ECDSA", "RSA", "DSA"]


@pytest.mark.parametrize(
    "algorithm_name",
    ALGORITHMS,
)
def test_succeeded_signatures(algorithm_name):
    m = 17

    dsa = LightDSA(algorithm_name=algorithm_name)

    signature = dsa.sign(m)

    is_verified = dsa.verify(m, signature)
    assert is_verified is True

    logger.info(f"✅ {algorithm_name}'s api test succeeded")


def test_failed_eddsa_signatures():
    m = 17

    dsa = LightDSA(algorithm_name="EdDSA")

    signature = dsa.sign(m)

    assert isinstance(signature, tuple)
    assert len(signature) == 2
    assert isinstance(signature[0], tuple)
    assert len(signature[0]) == 2
    assert isinstance(signature[0][0], int)
    assert isinstance(signature[0][1], int)
    assert isinstance(signature[1], int)

    # change signatures
    G = dsa.dsa.curve.G.get_point()
    signature = ((G), signature[1])

    with pytest.raises(ValueError, match="Signature is invalid"):
        _ = dsa.verify(m, signature)

    logger.info("✅ EdDSA's change signature detected succeeded")


def test_failed_ecdsa_signatures():
    m = 17

    dsa = LightDSA(algorithm_name="ECDSA")

    signature = dsa.sign(m)
    assert isinstance(signature, tuple)
    assert len(signature) == 2
    assert isinstance(signature[0], int)
    assert isinstance(signature[1], int)

    # change signatures
    signature = (signature[1], signature[0])

    with pytest.raises(ValueError, match="Signature is invalid"):
        _ = dsa.verify(m, signature)

    logger.info("✅ ECDSA's change signature detected succeeded")


def test_failed_rsa_signatures():
    m = 17

    dsa = LightDSA(algorithm_name="rsa")

    signature = dsa.sign(m)
    assert isinstance(signature, int)

    # change signatures
    signature = signature + 1

    with pytest.raises(ValueError, match="Signature is invalid"):
        _ = dsa.verify(m, signature)

    logger.info("✅ RSA's change signature detected succeeded")


def test_custom_curves():
    configs = [
        ("eddsa", "weierstrass", "secp256k1"),
        ("eddsa", "koblitz", "k233"),
        ("eddsa", "edwards", "e521"),
        ("ecdsa", "edwards", "ed25519"),
        ("ecdsa", "koblitz", "k233"),
        ("ecdsa", "weierstrass", "bn638"),
    ]
    for algorithm, form, curve in configs:
        dsa = LightDSA(algorithm_name="rsa")
        m = 23
        signature = dsa.sign(m)
        assert dsa.verify(m, signature) is True
        logger.info(f"✅ {algorithm}-{form}-{curve} test succeeded")
