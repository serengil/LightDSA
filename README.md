# LightDSA

<div align="center">

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lightdsa?period=total&units=international_system&left_color=grey&right_color=blue&left_text=downloads)](https://pepy.tech/project/lightdsa)
[![Stars](https://img.shields.io/github/stars/serengil/LightDSA?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/LightDSA/stargazers)
[![Tests](https://github.com/serengil/LightDSA/actions/workflows/tests.yml/badge.svg)](https://github.com/serengil/LightDSA/actions/workflows/tests.yml)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/LightPHE/blob/master/LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2408.05219-b31b1b.svg?logo=arXiv)](https://arxiv.org/abs/2408.05219)

[![Blog](https://img.shields.io/:blog-sefiks.com-blue.svg?style=flat&logo=wordpress)](https://sefiks.com)
[![YouTube](https://img.shields.io/:youtube-@sefiks-red.svg?style=flat&logo=youtube)](https://www.youtube.com/@sefiks?sub_confirmation=1)
[![Twitter](https://img.shields.io/:follow-@serengil-blue.svg?style=flat&logo=x)](https://twitter.com/intent/user?screen_name=serengil)

[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3Dserengil%26type%3Dpatrons&style=flat)](https://www.patreon.com/serengil?repo=lightphe)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/serengil?logo=GitHub&color=lightgray)](https://github.com/sponsors/serengil)
[![Buy Me a Coffee](https://img.shields.io/badge/-buy_me_a%C2%A0coffee-gray?logo=buy-me-a-coffee)](https://buymeacoffee.com/serengil)

</div>

<p align="center"><img src="https://raw.githubusercontent.com/serengil/LightDSA/master/images/shield.png" width="200" height="240"></p>

LightDSA is a lightweight digital signature algorithm library for Python. It is a hybrid library supporting [Elliptic Curve Digital Signature Algorithm (ECDSA)](https://sefiks.com/2018/02/16/elegant-signatures-with-elliptic-curve-cryptography/) and [Edwards-Curve Digital Signature Algorithm (EdDSA)](https://sefiks.com/2018/12/24/a-gentle-introduction-to-edwards-curve-digital-signature-algorithm-eddsa/), [RSA](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/) and [DSA](https://sefiks.com/2023/06/14/digital-signature-algorithm-dsa-in-python-from-scratch/).

# Installation [![PyPI](https://img.shields.io/pypi/v/lightdsa.svg)](https://pypi.org/project/lightdsa/)

The easiest way to install the LightDSA package is to install it from python package index (PyPI).

```shell
pip install lightdsa
```

Then you will be able to import the library and use its functionalities.

```python
from lightdsa import LightDSA
```

# Usage

Once you initialize a LightDSA object with a specific DSA algorithm, such as ECDSA, EdDSA, or RSA, it will generate the private and public keys for your cryptosystem.

```python
# built a cryptosystem
dsa = LightDSA(algorithm_name = "eddsa") # or ecdsa, rsa

# export keys
dsa.export_keys("secret.txt")
dsa.export_keys("public.txt", public = True)
del dsa
```

If you wish to use a pre-existing exported cryptosystem, you should specify the exported key file during initialization. This will allow you to sign messages using the private key and verify messages using the public key.

```python
# restore the cryptosystem for signer side
signer_dsa = LightDSA(algorithm_name = "eddsa", key_file = "secret.txt")

message = "Hello, world!"
signature = signer_dsa.sign(message)

# restore the cryptosystem for the verifier side
verifier_dsa = LightDSA(algorithm_name = "eddsa", key_file = "public.txt")
verifier_dsa.verify(message, signature)
```

# Elliptic Curve Forms and Pre-Defined Curves

LightDSA supports [Weierstrass](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/), [Koblitz](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and [Edwards](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms and hundreds of pre-defined curves that can be adopted in ECDSA and EdDSA.

By default, ECDSA uses the Weierstrass form with the secp256k1 curve (the curve used by Bitcoin), while EdDSA uses the Edwards form with the ed25519 curve. However, you can switch the elliptic curve form and the specific curve for both ECDSA and EdDSA during the initialization of the LightDSA object. Meanwhile, the hashing algorithm is determined based on [the order of the elliptic curve](https://sefiks.com/2018/02/27/counting-points-on-elliptic-curves-over-finite-field/), which defines the number of points available over the finite field.

```python
dsa = LightDSA(
    algorithm_name = "eddsa",
    form_name = "edwards",
    curve_name = "ed448"
)
```

See [`curves`](https://github.com/serengil/LightECC#supported-curves) page for more details.

# Contributing

All PRs are more than welcome! If you are planning to contribute a large patch, please create an issue first to get any upfront questions or design decisions out of the way first.

You should be able run `make test` and `make lint` commands successfully before committing. Once a PR is created, GitHub test workflow will be run automatically and unit test results will be available in [GitHub actions](https://github.com/serengil/LightDSA/actions/workflows/tests.yml) before approval.

# Support

There are many ways to support a project - starring⭐️ the GitHub repo is just one 🙏

You can also support this work on [Patreon](https://www.patreon.com/serengil?repo=lightdsa), [GitHub Sponsors](https://github.com/sponsors/serengil) or [Buy Me a Coffee](https://buymeacoffee.com/serengil).

<a href="https://www.patreon.com/serengil?repo=lightdsa">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/patreon.png" width="30%" height="30%">
</a>

<a href="https://buymeacoffee.com/serengil">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/bmc-button.png" width="25%" height="25%">
</a>

Also, your company's logo will be shown on README on GitHub if you become sponsor in gold, silver or bronze tiers.

# Citation

Please cite LightDSA in your publications if it helps your research. Here is its BibTex entry:

```BibTeX
@misc{serengil2025lightdsa
    author       = {Serengil, Sefik Ilkin},
    title        = {LightDSA: A Lightweight Digital Signature Algorithm Library for Python},
    year         = {2025},
    publisher    = {GitHub},
    howpublished = {https://github.com/serengil/LightDSA},
}
```

# License

LightDSA is licensed under the MIT License - see [`LICENSE`](https://github.com/serengil/LightDSA/blob/master/LICENSE) for more details.