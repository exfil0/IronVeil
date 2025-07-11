from .config import logger, USER_AGENTS, COMMON_PORTS, load_api_keys
from .utils.dns_utils import initialize_dns_resolver, detect_wildcard
from .utils.http_utils import get_session_with_proxy, make_request
from .utils.output_utils import write_to_output, export_csv
from .phases.passive import *
from .phases.active import active_brute_force, active_permutation, active_zone_transfer
from .phases.probing import probe_http_https
from .phases.scanning import check_open_ports
from .phases.recursion import recursive_enumerate

from collections import deque
import random
import time
import sys
import re
import json
import os
import hashlib
import socket
import backoff
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import csv
import threading

class SubdomainEnumerator:
    def __init__(self, domain, wordlist_path=None, threads=20, timeout=10, verbose=False, output_file=None, api_keys=None, recursion_depth=0, proxy_list_path=None, do_probe=True, do_port_scan=False, rate_limit_delay_per_thread=0.0):
        self.domain = domain.lower()
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        
        self.output_file = output_file
        self.output_jsonl_file = output_file.replace('.txt', '.jsonl') if output_file else None
        self.output_csv_file = output_file.replace('.txt', '.csv') if output_file else None
        
        self.api_keys = api_keys if api_keys else load_api_keys()
        self.recursion_depth = recursion_depth
        self.proxy_list_path = proxy_list_path
        self.do_probe = do_probe
        self.do_port_scan = do_port_scan
        self.rate_limit_delay_per_thread = rate_limit_delay_per_thread

        # Shared data structures with a single lock for all access (simpler and safer)
        self.found_subdomains = set() # Stores all unique subdomain strings discovered
        # Stores comprehensive data for each resolved subdomain (DNS, probe, port scan)
        self.resolved_subdomains_data = {} 
        self.data_lock = threading.Lock() 

        # Setup proxies, DNS resolvers, and wildcard detection
        self.proxies = self._load_proxies() 
        self.resolvers = deque([
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', # Google, Cloudflare
            '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', # Quad9, OpenDNS
            '76.76.19.19', '76.76.19.20', # Control D
        ])
        initialize_dns_resolver(self)
        self.wildcard_ip_and_content_hash = detect_wildcard(self)

        # Set verbosity for logger
        if self.verbose:
            logger.setLevel(logging.DEBUG)

    def _load_proxies(self):
        """Loads proxies from a file (one per line) or returns [None] for direct connection."""
        if not self.proxy_list_path or not os.path.exists(self.proxy_list_path):
            logger.warning("No proxy list found or specified. Continuing without proxies for HTTP/S probing.")
            return [None] # Use None to indicate direct connection
        
        with open(self.proxy_list_path, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        
        if not proxies:
            logger.warning("Proxy file is empty. Continuing without proxies.")
            proxies = [None]
        else:
            logger.info(f"Loaded {len(proxies)} proxies from {self.proxy_list_path}.")
        return proxies

    # (Add _resolve_subdomain, _add_found, _probe_http_https, _check_open_ports methods here from the original script)

    # Run methods (run, run_recursive_phase, phase_*)
    # (Copy from original, adjusting imports as needed)

# Note: Due to length, I've truncated the class body. Copy the full methods from the user's provided code, replacing calls to utils/phases with imports (e.g., from .phases.passive import passive_certsh).
