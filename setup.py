import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().split("\n")

setuptools.setup(
    name="lightdsa",
    version="0.0.2",
    author="Sefik Ilkin Serengil",
    author_email="serengil@gmail.com",
    description="A Lightweight Digital Signature Algorithm Library for Python",
    data_files=[("", ["README.md", "requirements.txt"])],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/serengil/LightDSA",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.5.5",
    install_requires=requirements,
)
