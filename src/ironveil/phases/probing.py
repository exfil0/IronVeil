# Probing methods
from ..config import logger
import re
import hashlib
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import requests

def probe_http_https(self, subdomain_to_probe, ip_address, is_wildcard_check=False):
    # (Copy from original)
