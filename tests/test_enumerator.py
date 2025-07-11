import pytest
from ironveil.enumerator import SubdomainEnumerator

def test_enumerator_init():
    enum = SubdomainEnumerator(domain="example.com")
    assert enum.domain == "example.com"
    # Add more tests (e.g., mock DNS for _resolve_subdomain)
