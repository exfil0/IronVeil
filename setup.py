from setuptools import setup, find_packages

setup(
    name="ironveil",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "requests",
        "dnspython",
        "backoff",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "ironveil = ironveil.cli:main",
        ],
    },
    author="exfil0",
    description="Militarized Subdomain Enumerator and Verifier",
    license="MIT",
    keywords="subdomain enumeration recon security",
    url="https://github.com/exfil0/IronVeil",
)
