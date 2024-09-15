from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cfp",
    version="0.1.0",
    author="CFP Research Team",
    description="Convergent Flow Protocol - A research blockchain prototype",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=[
        "networkx>=3.2",
        "py-ecc>=6.0.0",
        "pycryptodome>=3.19.0",
        "pydantic>=2.5.0",
        "click>=8.1.0",
        "python-dotenv>=1.0.0",
        "colorlog>=6.7.0",
    ],
    entry_points={
        "console_scripts": [
            "cfp=cfp.cli.main:cli",
        ],
    },
)
