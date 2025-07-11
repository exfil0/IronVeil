import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import time
import json
import random
from collections import deque
import sys
import threading
from urllib.parse import urlparse
import os
import hashlib
import socket
import backoff
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import csv

# --- Global Configuration & Setup ---
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # Suppress SSL warnings

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Default logging level
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 10; Mobile; rv:90.0) Gecko/90.0 Firefox/90.0',
    'Googlebot/2.1 (+http://www.google.com/bot.html)', # Bot user agent for stealth
    'bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0' # Firefox
]

# --- Main Enumerator Class ---
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
        
        self.api_keys = api_keys if api_keys else {}
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
        self._initialize_dns_resolver()
        self.wildcard_ip_and_content_hash = self._detect_wildcard()

        # Set verbosity for logger
        if self.verbose:
            logger.setLevel(logging.DEBUG)

    def _initialize_dns_resolver(self):
        """Initializes dns.resolver with custom settings."""
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = self.timeout / 2 # DNS resolution needs to be fast
        self.dns_resolver.lifetime = self.timeout
        # Ensure at least one resolver is set for initial operations
        if self.resolvers:
            self.dns_resolver.nameservers = [self.resolvers[0]]
        else:
            logger.error("No DNS resolvers configured! DNS resolution will fail.")

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

    def _get_session_with_proxy(self):
        """Returns a requests.Session object with a randomly selected proxy and User-Agent."""
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        
        proxy_url = random.choice(self.proxies)
        if proxy_url:
            session.proxies = {'http': proxy_url, 'https': proxy_url}
        
        return session

    @backoff.on_exception(backoff.expo, Exception, max_tries=5, jitter=backoff.full_jitter, logger=logger)
    def _resolve_subdomain(self, subdomain_prefix):
        """
        Attempts to resolve a subdomain, rotating resolvers, handling wildcard detection,
        and extracting details from various DNS record types. Updates resolved_subdomains_data.
        """
        full_domain = f"{subdomain_prefix}.{self.domain}"
        
        # Apply rate limit delay before DNS resolution (per thread)
        if self.rate_limit_delay_per_thread > 0:
            time.sleep(self.rate_limit_delay_per_thread * random.uniform(0.8, 1.2))

        # Check if already resolved/processed with lock
        with self.data_lock:
            if full_domain in self.resolved_subdomains_data and self.resolved_subdomains_data[full_domain].get('is_resolved', False):
                return self.resolved_subdomains_data[full_domain] # Already processed
            # Initialize placeholder if not seen as resolved yet
            if full_domain not in self.resolved_subdomains_data:
                 self.resolved_subdomains_data[full_domain] = {'domain': full_domain, 'is_resolved': False}


        current_resolver_ip = self.resolvers[0]
        self.dns_resolver.nameservers = [current_resolver_ip]
        
        try:
            # --- Initial A/AAAA Record Resolution for IP ---
            resolved_ip_v4 = []
            resolved_ip_v6 = []
            primary_resolved_ip = None

            for rtype in ['A', 'AAAA']:
                try:
                    answers = self.dns_resolver.resolve(full_domain, rtype)
                    if rtype == 'A':
                        resolved_ip_v4 = [str(a) for a in answers]
                    else: # AAAA
                        resolved_ip_v6 = [str(a) for a in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e: logger.debug(f"Error resolving {rtype} for {full_domain}: {e}")
            
            if resolved_ip_v4: primary_resolved_ip = resolved_ip_v4[0]
            elif resolved_ip_v6: primary_resolved_ip = resolved_ip_v6[0]

            if not primary_resolved_ip: # No A or AAAA records found after trying both
                with self.data_lock:
                     self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'no_a_aaaa_record'})
                     self._write_to_output(full_domain, self.resolved_subdomains_data[full_domain])
                return None

            # --- Smart Wildcard Filter Check ---
            is_wildcard_false_positive = False
            if self.wildcard_ip_and_content_hash and primary_resolved_ip == self.wildcard_ip_and_content_hash['ip']:
                if self.do_probe:
                    # Probe to differentiate based on content.
                    probe_info = self._probe_http_https(full_domain, primary_resolved_ip, is_wildcard_check=True)
                    if probe_info and probe_info.get('live_status_code') and probe_info['live_status_code'] < 400:
                        content_hash_match = (probe_info.get('content_hash') == self.wildcard_ip_and_content_hash['content_hash'])
                        title_match = (probe_info.get('title') == self.wildcard_ip_and_content_hash['title'])

                        if content_hash_match or title_match: 
                            is_wildcard_false_positive = True
                            logger.debug(f" [-] Skipping {full_domain} due to wildcard match (IP & content/title).")
                        else:
                            logger.debug(f" [+] {full_domain} resolves to wildcard IP but has UNIQUE content. Keeping.")
                    else: # Wildcard IP, but no live HTTP/S response for it
                        is_wildcard_false_positive = True
                        logger.debug(f" [-] Skipping {full_domain} (Wildcard IP, and no live HTTP/S content).")
                else: # IP-only wildcard filtering if probing is disabled
                    is_wildcard_false_positive = True
                    logger.debug(f" [-] Skipping {full_domain} due to wildcard match (IP only, probing disabled).")

            if is_wildcard_false_positive:
                with self.data_lock:
                     self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'wildcard_filtered'})
                     self._write_to_output(full_domain, self.resolved_subdomains_data[full_domain])
                return None

            # --- Comprehensive DNS Record Collection ---
            # Initialize with A/AAAA already found
            all_records = {'A': resolved_ip_v4, 'AAAA': resolved_ip_v6, 'CNAME': [], 'MX': [], 'NS': [], 'TXT': []}
            for rtype in ['CNAME', 'MX', 'NS', 'TXT']:
                try:
                    answers = self.dns_resolver.resolve(full_domain, rtype)
                    all_records[rtype] = [str(a).rstrip('.') for a in answers] # Remove trailing dots
                    
                    # Extract subdomains from record answers
                    for ans in answers:
                        target_sub = None
                        if rtype == 'CNAME' and hasattr(ans, 'target'):
                            target_sub = str(ans.target).rstrip('.')
                        elif rtype == 'MX' and hasattr(ans, 'exchange'):
                            target_sub = str(ans.exchange).rstrip('.')
                        elif rtype == 'NS' and hasattr(ans, 'target'):
                            # NS records in dnspython have .target for the name
                            target_sub = str(ans.target).rstrip('.')
                        
                        if target_sub and target_sub.endswith(self.domain) and target_sub != full_domain:
                            self._add_found(target_sub) # Add to general found_subdomains set for later processing

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass # Expected if record type doesn't exist for this domain
                except Exception as e: logger.debug(f"Error resolving {rtype} for {full_domain}: {e}")

            # --- Store Comprehensive DNS Data ---
            with self.data_lock:
                self.resolved_subdomains_data[full_domain].update({
                    'is_resolved': True,
                    'ip_v4': all_records['A'], 'ip_v6': all_records['AAAA'],
                    'cname': all_records['CNAME'], 'mx': all_records['MX'], 'ns': all_records['NS'], 'txt': all_records['TXT'],
                    'primary_ip': primary_resolved_ip, # The first A or AAAA IP
                    # Initialize probe and port scan data
                    'live_status_code': None, 'is_live_http': False, 'is_live_https': False,
                    'title': None, 'server_header': None, 'x_powered_by': None,
                    'content_hash': None, 'cert_cn': None, 'cert_sans': [],
                    'open_ports': []
                })
            
            self._write_to_output(full_domain, self.resolved_subdomains_data[full_domain]) # Write initial DNS data
            
            logger.debug(f" [+] Resolved DNS for: {full_domain}")
            return self.resolved_subdomains_data[full_domain] # Return the comprehensive data dict

        except Exception as e:
            logger.error(f" [!] Critical DNS resolution error for {full_domain}: {e}")
            with self.data_lock:
                 self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'resolution_error', 'error_msg': str(e)})
                 self._write_to_output(full_domain, self.resolved_subdomains_data[full_domain])
            raise # Re-raise to trigger backoff for transient issues

        finally:
            self.resolvers.rotate(-1) # Rotate resolver for next attempt

    def _add_found(self, subdomain_string):
        """Adds a newly discovered subdomain string to the master set (thread-safe)."""
        normalized_subdomain = subdomain_string.lower().strip().rstrip('.')
        
        # Filter out invalid or out-of-scope subdomains
        if (not normalized_subdomain.endswith(self.domain) or # Not part of target domain
            '*' in normalized_subdomain or # Wildcard
            normalized_subdomain.count('.') < self.domain.count('.') or # Parent domain or TLD
            normalized_subdomain == self.domain): # Exact match for main domain
            return

        # Ensure it starts with a valid character for a hostname
        if not re.match(r'^[a-z0-9]', normalized_subdomain.split('.')[0]):
            return

        with self.data_lock:
            if normalized_subdomain not in self.found_subdomains:
                self.found_subdomains.add(normalized_subdomain)
                # Initialize an entry for this domain even if not yet resolved, will be filled later
                if normalized_subdomain not in self.resolved_subdomains_data:
                    self.resolved_subdomains_data[normalized_subdomain] = {'domain': normalized_subdomain, 'is_resolved': False}
                logger.debug(f" [A] Added to discovery queue: {normalized_subdomain}")

    def _write_to_output(self, subdomain, data):
        """Appends subdomain data to JSONL file (thread-safe)."""
        if self.output_jsonl_file:
            try:
                with self.data_lock: # Ensure only one thread writes at a time to prevent file corruption
                    with open(self.output_jsonl_file, 'a') as f:
                        f.write(json.dumps(data) + '\n')
            except Exception as e:
                logger.error(f" [!] Error writing to JSONL output for {subdomain}: {e}")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=5, jitter=backoff.full_jitter, logger=logger)
    def _make_request(self, url, method="GET", json_data=None, data=None, headers=None, allow_redirects=True):
        """Wrapper for requests with user agent rotation, proxy, and error handling."""
        session = self._get_session_with_proxy() # Get session with fresh proxy & UA
        req_headers = session.headers.copy()
        if headers:
            req_headers.update(headers)
        
        # Introduce per-thread delay if configured
        if self.rate_limit_delay_per_thread > 0:
            time.sleep(self.rate_limit_delay_per_thread * random.uniform(0.8, 1.2))

        response = session.request(method, url, json=json_data, data=data, timeout=self.timeout, headers=req_headers, allow_redirects=allow_redirects)
        response.raise_for_status() # Raise HTTPError for bad status codes (4xx or 5xx)
        return response

    def _detect_wildcard(self):
        """
        Detects wildcard DNS responses by querying a non-existent subdomain.
        Also attempts to get its typical HTTP content hash and title for smarter false positive filtering.
        """
        random_sub_prefix = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=15))}-{int(time.time())}"
        random_full_domain = f"{random_sub_prefix}.{self.domain}"
        
        resolved_ip = None
        try:
            a_answers = self.dns_resolver.resolve(random_full_domain, 'A')
            resolved_ip = str(a_answers[0])
            logger.info(f" [!] Potentially detected wildcard IP for {self.domain}: {resolved_ip}.")
        except Exception:
            logger.debug(f" [.] No A record for random subdomain {random_full_domain}. No wildcard IP detected so far.")
            return None # No A record, likely no wildcard that resolves to an IP.

        # If an IP is found, attempt HTTP probe to get a content hash and title
        if resolved_ip and self.do_probe:
            try:
                # Use a deeper timeout for wildcard check, as it's critical
                probe_info = self._probe_http_https(random_full_domain, resolved_ip, is_wildcard_check=True)
                if probe_info and probe_info.get('live_status_code') and probe_info['live_status_code'] < 400:
                    logger.warning(f" [!] Wildcard DNS for {self.domain} confirmed. IP: {resolved_ip}. Content hash/title will be used for filtering.")
                    return {
                        'ip': resolved_ip,
                        'content_hash': probe_info.get('content_hash'),
                        'title': probe_info.get('title')
                    }
                else:
                    logger.warning(f" [!] Wildcard DNS for {self.domain} detected (IP: {resolved_ip}), but no live HTTP/S content found at that IP for random host. IP-only filtering will be used.")
            except Exception as e:
                logger.warning(f" [!] Error during wildcard HTTP probe for {self.domain} ({resolved_ip}): {e}. Proceeding with IP-only wildcard detection.")
        
        # Fallback: If no probe or probe failed, just use the IP for basic wildcard filtering
        return {'ip': resolved_ip, 'content_hash': None, 'title': None} if resolved_ip else None
    
    def _probe_http_https(self, subdomain_to_probe, ip_address, is_wildcard_check=False):
        """
        Probes HTTP and HTTPS for a given subdomain, extracts key info (headers, title, content hash, cert SANs).
        Updates self.resolved_subdomains_data for non-wildcard checks.
        """
        probe_results = {
            'live_status_code': None, 'is_live_http': False, 'is_live_https': False,
            'final_url_http': None, 'final_url_https': None,
            'server_header': None, 'x_powered_by': None, 'title': None, 'content_hash': None,
            'cert_cn': None, 'cert_sans': []
        }

        # --- HTTPS Probe ---
        try:
            session = self._get_session_with_proxy()
            session.verify = False # Disable SSL validation, we'll parse cert directly
            
            response = session.get(f"https://{subdomain_to_probe}", timeout=self.timeout, allow_redirects=True)
            response.raise_for_status()
            
            probe_results['is_live_https'] = True
            probe_results['live_status_code'] = response.status_code
            probe_results['final_url_https'] = response.url
            
            probe_results['server_header'] = response.headers.get('Server')
            probe_results['x_powered_by'] = response.headers.get('X-Powered-By')

            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
            if title_match: probe_results['title'] = title_match.group(1).strip()
            probe_results['content_hash'] = hashlib.sha256(response.content[:8192]).hexdigest() # Hash first 8KB

            # --- Extract SSL Certificate Information ---
            try:
                # Use ip_address for cert connection to avoid strict hostname checks
                cert_pem = ssl.get_server_certificate((ip_address, 443)) 
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                
                cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attr: probe_results['cert_cn'] = cn_attr[0].value
                
                try: # Subject Alternative Names
                    alt_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    for entry in alt_names.value.get_values_for_type(x509.DNSName):
                        probe_results['cert_sans'].append(entry)
                        # Add new subdomains discovered from cert SANs (crucial discovery method!)
                        if entry.endswith(self.domain) and entry not in self.found_subdomains:
                            self._add_found(entry) 
                except x509.ExtensionNotFound: pass # No SANs
                except Exception as e: logger.debug(f"Error parsing SANs for {subdomain_to_probe}: {e}")

            except Exception as e:
                logger.debug(f"Error fetching/parsing cert for {subdomain_to_probe}: {e}")
            
            logger.debug(f" [+] HTTPS live: {subdomain_to_probe} (Status: {response.status_code})")

        except (requests.exceptions.SSLError, ssl.SSLError) as e:
            logger.debug(f" [!] HTTPS SSL error for {subdomain_to_probe}. Trying HTTP. Error: {e}")
        except requests.exceptions.HTTPError as e: # 4xx/5xx errors
            probe_results['live_status_code'] = e.response.status_code
            logger.debug(f" [!] HTTPS HTTPError for {subdomain_to_probe}: {e.response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.debug(f" [!] HTTPS probe failed for {subdomain_to_probe}: {type(e).__name__} - {e}")
        except Exception as e:
            logger.debug(f" [!] Unknown error during HTTPS probe for {subdomain_to_probe}: {e}")

        # --- HTTP Probe (only if HTTPS not successful or this is a wildcard check) ---
        # For wildcard checks, we always attempt both HTTP and HTTPS to compare content.
        # Otherwise, if HTTPS was fine, we might skip HTTP for efficiency.
        if is_wildcard_check or not probe_results['is_live_https']: 
            try:
                session = self._get_session_with_proxy()
                response = session.get(f"http://{subdomain_to_probe}", timeout=self.timeout, allow_redirects=True)
                response.raise_for_status()
                
                probe_results['is_live_http'] = True
                if not probe_results['is_live_https']: # Only update overall status if HTTPS wasn't live
                    probe_results['live_status_code'] = response.status_code
                probe_results['final_url_http'] = response.url

                # Populate headers, title, hash if not already from HTTPS
                if not probe_results['server_header']: probe_results['server_header'] = response.headers.get('Server')
                if not probe_results['x_powered_by']: probe_results['x_powered_by'] = response.headers.get('X-Powered-By')
                if not probe_results['title']:
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                    if title_match: probe_results['title'] = title_match.group(1).strip()
                if not probe_results['content_hash']: probe_results['content_hash'] = hashlib.sha256(response.content[:8192]).hexdigest()

                logger.debug(f" [+] HTTP live: {subdomain_to_probe} (Status: {response.status_code})")

            except requests.exceptions.HTTPError as e: # 4xx/5xx errors
                if not probe_results['is_live_https']: # Only update overall status if HTTPS wasn't already live
                    probe_results['live_status_code'] = e.response.status_code
                logger.debug(f" [!] HTTP HTTPError for {subdomain_to_probe}: {e.response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.debug(f" [!] HTTP probe failed for {subdomain_to_probe}: {type(e).__name__} - {e}")
            except Exception as e:
                logger.debug(f" [!] Unknown error during HTTP probe for {subdomain_to_probe}: {e}")

        if not is_wildcard_check: # Only update global data if not a wildcard check call
            with self.data_lock:
                 # Update only relevant probe fields in the existing dictionary
                 current_data = self.resolved_subdomains_data.get(subdomain_to_probe, {'domain': subdomain_to_probe, 'is_resolved': False})
                 current_data.update(probe_results)
                 self.resolved_subdomains_data[subdomain_to_probe] = current_data
            self._write_to_output(subdomain_to_probe, self.resolved_subdomains_data[subdomain_to_probe]) # Update JSONL
        
        return probe_results # Return probe info for immediate use (e.g., wildcard check)


    # --- Port Scanning ---
    def _check_open_ports(self, subdomain, ip_address, common_ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]):
        """Performs a quick connectivity check on common ports for a given IP."""
        if not ip_address: # Need an IP to scan
             logger.debug(f" [!] No IP provided for port scan of {subdomain}.")
             return
        
        open_ports = []
        for port in common_ports:
            # Apply rate limit delay (if any) before attempting port scan
            if self.rate_limit_delay_per_thread > 0:
                time.sleep(self.rate_limit_delay_per_thread * random.uniform(0.8, 1.2))

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5) # Short timeout for quick checks
            try:
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                    logger.debug(f" [+] Port {port} open on {subdomain} ({ip_address})")
            except socket.error as e:
                logger.debug(f" [!] Port scan error on {subdomain}:{port}: {e}")
            finally:
                sock.close()
        
        if open_ports:
            with self.data_lock:
                # Update the existing entry for this subdomain
                if subdomain in self.resolved_subdomains_data:
                    self.resolved_subdomains_data[subdomain]['open_ports'] = open_ports
                else: # Should already be initialized by _resolve_subdomain
                    self.resolved_subdomains_data[subdomain] = {'domain': subdomain, 'open_ports': open_ports}
            self._write_to_output(subdomain, self.resolved_subdomains_data[subdomain]) # Update JSONL
        
        return open_ports

    # --- Passive Enumeration Sources ---
    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_certsh(self):
        """Fetches subdomains from crt.sh certificate transparency logs."""
        logger.info(f"[*] Running crt.sh passive scan for {self.domain}...")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        response = self._make_request(url)
        if response:
            try:
                # crt.sh can return multiple JSON objects not enclosed in an array
                text = response.text.replace('}{', '},{')
                data = json.loads(f"[{text}]")
                for entry in data:
                    name_value = entry.get('name_value', '')
                    subdomains_raw = re.split(r'\n|,', name_value)
                    for subd in subdomains_raw:
                        self._add_found(subd)
            except json.JSONDecodeError as e:
                logger.error(f" [!] JSON decode error from crt.sh for {self.domain}: {e}")
            except Exception as e:
                logger.error(f" [!] Error processing crt.sh data: {e}")
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from crt.sh.")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_hackertarget(self):
        """Fetches subdomains from hackertarget.com online tool."""
        logger.info(f"[*] Running hackertarget.com passive scan for {self.domain}...")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        response = self._make_request(url)
        if response:
            for line in response.text.splitlines():
                parts = line.split(',')
                if len(parts) > 0:
                    self._add_found(parts[0])
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from hackertarget.com.")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_virustotal(self):
        """Fetches subdomains from VirusTotal (requires API key)."""
        logger.info(f"[*] Running VirusTotal passive scan for {self.domain}...")
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            logger.warning(" [!] No VirusTotal API key provided. Skipping VirusTotal scan.")
            return

        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = self._get_session_with_proxy().headers # Get a fresh set of headers
        headers['x-apikey'] = api_key
        
        response = self._make_request(url, headers=headers)
        if response:
            try:
                data = response.json()
                for entry in data.get('data', []):
                    self._add_found(entry.get('id', ''))
            except json.JSONDecodeError as e:
                logger.error(f" [!] JSON decode error from VirusTotal for {self.domain}: {e}")
            except Exception as e:
                logger.error(f" [!] Error processing VirusTotal data: {e}")
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from VirusTotal.")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_wayback(self):
        """Fetches subdomains from Wayback Machine's CDX API."""
        logger.info(f"[*] Running Wayback Machine passive scan for {self.domain}...")
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
        response = self._make_request(url)
        if response:
            try:
                data = response.json()
                if data and len(data) > 1:  # First entry is header
                    for entry in data[1:]:
                        url_key = entry[0] # Correct index for urlkey
                        # Robust parsing of SURT format or regular URL
                        match = re.search(r'\((.*?)\)', url_key)
                        if match: # SURT format (e.g., com,example,www)
                            host = '.'.join(reversed(match.group(1).split(','))).strip(':*')
                        else: # Regular URL or hostname
                            parsed_url = urlparse(url_key)
                            host = parsed_url.netloc or parsed_url.path.split('/')[0]
                        self._add_found(host)
            except json.JSONDecodeError as e:
                logger.error(f" [!] JSON decode error from Wayback Machine for {self.domain}: {e}")
            except Exception as e:
                logger.error(f" [!] Error processing Wayback Machine data: {e}")
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from Wayback Machine.")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_bufferover(self):
        """Fetches subdomains from BufferOver.run DNS dump."""
        logger.info(f"[*] Running BufferOver.run passive scan for {self.domain}...")
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        response = self._make_request(url)
        if response:
            try:
                data = response.json()
                for entry in data.get('FDNS_A', []) + data.get('RDNS', []):
                    parts = entry.split(',')
                    self._add_found(parts[-1] if len(parts) > 1 else entry)
            except json.JSONDecodeError as e:
                logger.error(f" [!] JSON decode error from BufferOver.run for {self.domain}: {e}")
            except Exception as e:
                logger.error(f" [!] Error processing BufferOver.run data: {e}")
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from BufferOver.run.")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_alienvault(self):
        """Fetches subdomains from AlienVault OTX."""
        logger.info(f"[*] Running AlienVault OTX passive scan for {self.domain}...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        response = self._make_request(url)
        if response:
            try:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    self._add_found(entry.get('hostname', ''))
            except json.JSONDecodeError as e:
                logger.error(f" [!] JSON decode error from AlienVault for {self.domain}: {e}")
            except Exception as e:
                logger.error(f" [!] Error processing AlienVault data: {e}")
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from AlienVault.")

    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def passive_dnsdumpster(self):
        """Fetches subdomains from DNSdumpster via a programmatic approach (unofficial API)."""
        logger.info(f"[*] Running DNSdumpster.com passive scan for {self.domain}...")
        url = "https://dnsdumpster.com/"
        try:
            response = self._make_request(url)
            csrftoken_match = re.search(r"name='csrfmiddlewaretoken' value='(.*?)'", response.text)
            if not csrftoken_match:
                raise ValueError("CSRF token not found. DNSdumpster.com site structure may have changed.")
            csrftoken = csrftoken_match.group(1)
            
            data = {
                'csrfmiddlewaretoken': csrftoken,
                'targetip': self.domain,
            }
            
            headers = self._get_session_with_proxy().headers # Fresh headers
            headers['Referer'] = url # Important for DNSdumpster
            
            response = self._make_request(url, method="POST", data=data, headers=headers)
            # Extract hostnames from the results table
            host_regex = re.compile(r'<td class="col-md-4">([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')</td>')
            for match in host_regex.finditer(response.text):
                self._add_found(match.group(1))
            
        except (requests.exceptions.RequestException, AttributeError, ValueError) as e:
            logger.error(f" [!] Error fetching from DNSdumpster.com: {e}. Site may have changed or blocked the request.")
        logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from DNSdumpster.")

    # --- Active Enumeration Methods ---
    def active_brute_force(self):
        """Performs brute-force subdomain enumeration using a wordlist."""
        if not self.wordlist_path:
            logger.info("[!] No wordlist path provided for brute-force. Skipping.")
            return

        logger.info(f"[*] Running brute-force scan for {self.domain} using {self.wordlist_path}...")
        subdomain_prefixes = []
        try:
            with open(self.wordlist_path, 'r') as f:
                # Only include prefixes not yet seen as resolved or currently in process
                with self.data_lock: # Protect access to self.resolved_subdomains_data
                    subdomain_prefixes = [
                        line.strip().lower() for line in f if line.strip() and 
                        f"{line.strip().lower()}.{self.domain}" not in self.resolved_subdomains_data
                    ]
            logger.info(f"Loaded {len(subdomain_prefixes)} unique prefixes for brute-force. (Already {len(self.found_subdomains)} discovered passively).")
        except FileNotFoundError:
            logger.error(f" [!] Wordlist not found at {self.wordlist_path}. Skipping brute-force.")
            return
        
        total_tasks = len(subdomain_prefixes)
        if total_tasks == 0:
            logger.info("[*] No new prefixes to brute-force based on current findings.")
            return

        completed_tasks = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._resolve_subdomain, prefix): prefix for prefix in subdomain_prefixes}
            
            for future in as_completed(futures):
                completed_tasks += 1
                try:
                    _ = future.result() # Processed internally by _resolve_subdomain
                except Exception as e:
                    logger.debug(f" [!] Error during brute-force for {futures[future]}: {e}")
                
                # Progress update
                if self.verbose and completed_tasks % 50 == 0:
                    current_resolved_count = sum(1 for s in self.resolved_subdomains_data if self.resolved_subdomains_data[s].get('is_resolved'))
                    progress = (completed_tasks / total_tasks) * 100
                    sys.stdout.write(f"\r [.] Brute-force Progress: {progress:.2f}% ({completed_tasks}/{total_tasks}) - Resolved: {current_resolved_count}")
                    sys.stdout.flush()
        sys.stdout.write(f"\r[*] Brute-force completed. Total subdomains discovered: {len(self.found_subdomains)}.\n")
        sys.stdout.flush()

    def active_permutation(self):
        """Generates permutations based on found subdomains and common patterns, then resolves them."""
        if not self.found_subdomains:
            logger.info("[!] No initial subdomains found for permutation generation. Skipping.")
            return

        logger.info(f"[*] Generating and resolving advanced permutations...")
        permutation_attempts = set()
        
        # Common parts for permutations (can be expanded)
        common_parts = [
            'dev', 'test', 'stage', 'qa', 'int', 'preprod', 'uat', 'dr', 'new', 'old', 'beta', 'alpha',
            'api', 'admin', 'auth', 'cdn', 'mail', 'webmail', 'ftp', 'docs', 'app', 'portal', 'secure',
            'dashboard', 'manage', 'support', 'status', 'vpn', 'proxy', 'store', 'shop', 'blog', 'news',
            'img', 'stats', 'login', 'sso', 'static', 'assets', 'internal',
            '01', '02', '03', '1', '2', '3', # Numbers
        ]
        dev_suffixes = ["-dev", "-test", "-stage"]
        subs_map = {'a': 's', 's': 'a', 'o': 'p', 'p': 'o', 'l': 'k', 'k': 'l'} # common keyboard adjacencies

        with self.data_lock:
            initial_subdomains_for_permuting = list(self.found_subdomains) # Get a snapshot of currently found

        for subdomain_full in initial_subdomains_for_permuting:
            # Extract just the prefix part (e.g., 'mail' from 'mail.example.com')
            # Ensure we're only working with the subdomain part, not the main domain
            try:
                base_prefix = subdomain_full.replace(f".{self.domain}", "")
                if base_prefix == "": continue # Skip main domain itself
            except ValueError: continue # Not a direct subdomain of target domain (e.g. sub-sub-domain)

            # 1. Direct prefix/suffix combinations
            for part in common_parts:
                permutation_attempts.add(f"{part}.{base_prefix}")      # e.g., dev.app
                permutation_attempts.add(f"{base_prefix}-{part}")     # e.g., app-dev
                permutation_attempts.add(f"{part}-{base_prefix}")     # e.g., dev-app
                permutation_attempts.add(f"{base_prefix}{part}")      # e.g., appdev
                permutation_attempts.add(f"{part}{base_prefix}")      # e.g., devapp

            # 2. Transposition/Typo variations (simple)
            if len(base_prefix) > 1:
                for i in range(len(base_prefix) - 1):
                    typo_prefix = list(base_prefix)
                    typo_prefix[i], typo_prefix[i+1] = typo_prefix[i+1], typo_prefix[i]
                    permutation_attempts.add(''.join(typo_prefix))

            # 3. Add/Remove common characters (e.g., dash, dot)
            for sfx in dev_suffixes:
                 if sfx in base_prefix: # If already has -dev, try without
                     permutation_attempts.add(base_prefix.replace(sfx, '')) # e.g. from app-dev to app
                 else: # If doesn't have -dev, try adding it
                     permutation_attempts.add(f"{base_prefix}{sfx}") # e.g. from app to app-dev

            # 4. Numeric increments (app01, app02)
            num_match = re.search(r'([a-zA-Z]+)(\d+)$', base_prefix) # Matches numbers at the end
            if num_match:
                alpha_part = num_match.group(1)
                num_part = int(num_match.group(2))
                num_len = len(num_match.group(2))
                for i in range(max(1, num_part - 5), num_part + 6): # Try a small range around the number
                    permutation_attempts.add(f"{alpha_part}{i:0{num_len}d}") # Maintain leading zeros

            # 5. Omissions
            for i in range(len(base_prefix)):
                omission = base_prefix[:i] + base_prefix[i+1:]
                if omission: permutation_attempts.add(omission)

            # 6. Repetitions
            for i in range(len(base_prefix)):
                repetition = base_prefix[:i] + base_prefix[i] + base_prefix[i:]
                permutation_attempts.add(repetition)

            # 7. Substitutions
            for i, char in enumerate(base_prefix):
                if char in subs_map:
                    sub = list(base_prefix)
                    sub[i] = subs_map[char]
                    permutation_attempts.add(''.join(sub))

        # Filter out attempts that are already in self.resolved_subdomains_data
        with self.data_lock:
            permutations_to_check = {p for p in permutation_attempts if f"{p}.{self.domain}" not in self.resolved_subdomains_data}
        
        # Limit the number of permutations to avoid overwhelming
        max_permutations_to_check = 20000 
        if len(permutations_to_check) > max_permutations_to_check:
            permutations_to_check = set(random.sample(list(permutations_to_check), max_permutations_to_check))
            logger.warning(f" [!] Limiting permutation checks to {max_permutations_to_check} to manage resources.")

        if not permutations_to_check:
            logger.info("[*] No new permutations generated to check.")
            return

        total_tasks = len(permutations_to_check)
        completed_tasks = 0

        logger.info(f"[*] Resolving {total_tasks} generated permutations...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._resolve_subdomain, prefix): prefix for prefix in permutations_to_check}
            
            for future in as_completed(futures):
                completed_tasks += 1
                try:
                    _ = future.result() # Processed internally by _resolve_subdomain
                except Exception as e:
                    logger.debug(f" [!] Error during permutation resolution for {futures[future]}: {e}")
                
                # Progress update: FIX applied here.
                if self.verbose and completed_tasks % 100 == 0:
                    current_resolved_count = sum(1 for s in self.resolved_subdomains_data if self.resolved_subdomains_data[s].get('is_resolved'))
                    progress = (completed_tasks / total_tasks) * 100 # Corrected calculation
                    sys.stdout.write(f"\r [.] Permutation Progress: {progress:.2f}% ({completed_tasks}/{total_tasks}) - Resolved: {current_resolved_count}")
                    sys.stdout.flush()
        sys.stdout.write(f"\r[*] Permutation scan completed. Total subdomains discovered: {len(self.found_subdomains)}.\n")
        sys.stdout.flush()

    @backoff.on_exception(backoff.expo, Exception, max_tries=3, jitter=backoff.full_jitter, logger=logger)
    def active_zone_transfer(self):
        """Attempts a DNS zone transfer (AXFR). Highly effective if successful, but rare."""
        logger.info(f"[*] Attempting DNS Zone Transfer (AXFR) for {self.domain}...")
        try:
            # Find authoritative nameservers for the domain
            ns_answers = self.dns_resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns.target) for ns in ns_answers]

            for ns_domain in nameservers:
                try:
                    # Resolve NS domain to IP
                    ns_ip = str(self.dns_resolver.resolve(ns_domain, 'A')[0])
                    transfer_resolver = dns.resolver.Resolver()
                    transfer_resolver.nameservers = [ns_ip]
                    transfer_resolver.timeout = self.timeout
                    transfer_resolver.lifetime = self.timeout
                    
                    logger.debug(f" [.] Attempting AXFR from {ns_domain} ({ns_ip})...")
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, relativize=False, timeout=self.timeout))
                    
                    for name, node in zone.nodes.items():
                        full_name = str(name).rstrip('.')
                        if full_name.endswith(self.domain): # Ensure subdomains are within scope
                           self._add_found(full_name) # Add to found_subdomains
                    logger.warning(f" [!!!] Zone transfer successful from {ns_domain}! This is a significant finding.")
                    return # Exit after first successful transfer
                except dns.exception.FormError:
                    logger.debug(f" [!] Zone transfer from {ns_domain} denied for {self.domain}.")
                except dns.resolver.NXDOMAIN:
                    logger.debug(f" [!] NS record for {ns_domain} did not resolve.")
                except Exception as e:
                    logger.debug(f" [!] Error during zone transfer from {ns_domain}: {e}")
        except dns.resolver.NXDOMAIN:
            logger.info(f" [!] Could not find nameservers for {self.domain}. Skipping zone transfer.")
        except Exception as e:
            logger.error(f" [!] Error setting up zone transfer: {e}")
        logger.info(f"[*] Zone transfer attempt completed. Total subdomains discovered: {len(self.found_subdomains)}.")

    def _recursive_enumerate(self, depth):
        """Recursively enumerates sub-subdomains based on found CNAME/NS or existing multi-level subdomains."""
        if depth < 0: return # Stop condition for recursion

        candidates_for_recursion = set()
        with self.data_lock:
            # Iterate over a copy to avoid modification during iteration
            for subd_data in list(self.resolved_subdomains_data.values()): # Process a snapshot
                if not subd_data.get('is_resolved'): continue # Only recurse on resolved entries

                # 1. Based on CNAME/NS targets
                for key in ['cname', 'ns']:
                    for target_name in subd_data.get(key, []):
                        # Ensure target is a subdomain of the original domain, and has more parts (is a sub-sub-domain)
                        if target_name.endswith(self.domain) and target_name.count('.') > self.domain.count('.'):
                            candidates_for_recursion.add(target_name)

                # 2. Based on existing multi-level subdomains (e.g., if app.dev.example.com is found, infer dev.example.com)
                current_domain_str = subd_data['domain']
                if current_domain_str.count('.') > self.domain.count() + 1: # Indicates a sub-sub-domain
                    # Extract the immediate parent as a new base domain for recursive lookup (e.g., dev.example.com)
                    parts = current_domain_str.split('.')
                    potential_new_base = ".".join(parts[1:]) 
                    # Ensure it's still part of the original domain and not the original domain itself
                    if potential_new_base.endswith(self.domain) and potential_new_base != self.domain:
                        candidates_for_recursion.add(potential_new_base)

        newly_found_in_recursion_cycle = set()
        for base_domain_for_recursion in candidates_for_recursion:
            # Avoid re-enumerating the exact same domain that was already the target
            if base_domain_for_recursion == self.domain: continue 
            
            logger.info(f"[*] Recursing into new base domain: {base_domain_for_recursion} (Depth Remaining: {depth})...")
            # Create a new enumerator instance for the recursive call
            # Crucially, pass api_keys and proxy_list_path for nested calls
            recursive_enumerator = SubdomainEnumerator(
                domain=base_domain_for_recursion,
                wordlist_path=self.wordlist_path,
                threads=self.threads // 2 if self.threads > 1 else 1, # Reduce threads for depth
                timeout=self.timeout,
                verbose=self.verbose,
                output_file=None, # Don't write separate files for sub-recursions
                api_keys=self.api_keys,
                recursion_depth=0, # Disable further recursion in this sub-enumerator if depth is 1
                proxy_list_path=self.proxy_list_path,
                do_probe=self.do_probe,
                do_port_scan=self.do_port_scan,
                rate_limit_delay_per_thread=self.rate_limit_delay_per_thread # Inherit rate limit
            )
            recursive_enumerator.run_recursive_phase() # Call specific phase for recursion

            # Merge results from the recursive call back into the main enumerator's data
            with self.data_lock:
                for dns_entry, data in recursive_enumerator.resolved_subdomains_data.items():
                    # Only add if it belongs to the *original* top-level domain and hasn't been seen
                    if dns_entry.endswith(self.domain) and dns_entry not in self.resolved_subdomains_data:
                        self.resolved_subdomains_data[dns_entry] = data
                        self.found_subdomains.add(dns_entry)
                        newly_found_in_recursion_cycle.add(dns_entry)
                        self._write_to_output(dns_entry, data) # Write newly discovered from recursion

        if newly_found_in_recursion_cycle:
            logger.info(f"[*] Discovered {len(newly_found_in_recursion_cycle)} new subdomains during recursion at depth {depth}.")
            # Potentially re-probe/re-scan these newly found ones here if depth > 0 and desired
            # For simplicity, they will be picked up in the final probing/scanning phases
            # if they were added to self.resolved_subdomains_data
            
            # --- Continue Recursion ---
            if depth > 1: # Proceed to next depth only if there's more to explore
                self._recursive_enumerate(depth - 1)
        else:
            logger.info(f"[*] No new subdomains found originating from depth {depth} recursion.")


    # --- Output & Reporting Functions ---
    def _export_csv(self):
        """Exports the comprehensive subdomain data to a CSV file."""
        if not self.output_csv_file: return
        
        logger.info(f"[*] Exporting detailed data to CSV: {self.output_csv_file}")
        
        # Define headers explicitly to control order and ensure all potential fields are present
        headers = [
            'domain', 'is_resolved', 'primary_ip', 'ip_v4', 'ip_v6', 'cname', 'mx', 'ns', 'txt',
            'is_live_http', 'is_live_https', 'live_status_code', 'final_url_http', 'final_url_https',
            'title', 'server_header', 'x_powered_by', 'content_hash',
            'cert_cn', 'cert_sans', 'open_ports', 'status', 'error_msg'
        ]
        
        with open(self.output_csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            with self.data_lock: # Ensure thread-safe read
                for domain, data in self.resolved_subdomains_data.items():
                    row = {}
                    for h in headers:
                        val = data.get(h, '')
                        # Convert lists to comma-separated strings for CSV cells
                        if isinstance(val, list):
                            row[h] = ', '.join(map(str, val))
                        else:
                            row[h] = val
                    writer.writerow(row)
        logger.info(f"[*] CSV export complete to {self.output_csv_file}")


    # --- Master Run Orchestration ---
    def run(self):
        """Orchestrates the entire subdomain enumeration and verification process."""
        logger.info(f"\n--- Initiating Operation Iron Veil: Hardened & Sharpened for {self.domain} ---")
        if self.wildcard_ip_and_content_hash and self.wildcard_ip_and_content_hash['ip']:
            logger.warning(f" [!] Wildcard DNS detected for {self.domain}. IP: {self.wildcard_ip_and_content_hash['ip']}. Responses matching its content will be filtered.")
            if not self.do_probe:
                logger.warning(" [!] Probing is disabled, wildcard filtering will rely on IP only, which may result in false positives.")

        self.phase_passive_recon()
        self.phase_active_dns_discovery()
        self.phase_live_host_verification()
        self.phase_port_scanning()
        self.phase_recursive_enumeration()
        self.phase_final_reporting()

    def run_recursive_phase(self):
        """Simplified run for nested recursive calls."""
        with self.data_lock: # Clear data for this recursive instance
            self.found_subdomains.clear()
            self.resolved_subdomains_data.clear()
        
        self.phase_passive_recon()
        self.phase_active_dns_discovery()
        self.phase_live_host_verification()
        # No port scanning or deeper recursion in nested calls by default
        # Merging of results happens in the parent _recursive_enumerate

    def phase_passive_recon(self):
        """Executes all passive reconnaissance methods."""
        logger.info("\n--- Phase 1: Passive Reconnaissance ---")
        self.passive_certsh()
        self.passive_hackertarget()
        self.passive_virustotal()
        self.passive_wayback()
        self.passive_bufferover()
        self.passive_alienvault()
        self.passive_dnsdumpster()
        time.sleep(2) # Give passive sources a moment to finish/cool down

    def phase_active_dns_discovery(self):
        """Executes active DNS enumeration methods."""
        logger.info("\n--- Phase 2: Active DNS Discovery ---")
        self.active_brute_force()
        self.active_permutation()
        self.active_zone_transfer() # Attempt zone transfer

    def phase_live_host_verification(self):
        """Performs HTTP/S probing if enabled."""
        if self.do_probe:
            logger.info("\n--- Phase 3: Live Host Probing & Verification ---")
            subdomains_to_probe = []
            with self.data_lock:
                # Get resolved domains that haven't been probed live yet
                subdomains_to_probe = [
                    d for d, data in self.resolved_subdomains_data.items() 
                    if data.get('is_resolved') and not data.get('is_live_http') and not data.get('is_live_https')
                ]
            
            if subdomains_to_probe:
                logger.info(f"[*] Probing {len(subdomains_to_probe)} resolved subdomains...")
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    # Pass full domain name and its primary IP
                    futures = {executor.submit(self._probe_http_https, name, self.resolved_subdomains_data[name].get('primary_ip')): name 
                               for name in subdomains_to_probe}
                    
                    completed_probes = 0
                    final_resolved_count_at_start = len(subdomains_to_probe) # For progress calculation
                    for future in as_completed(futures):
                        completed_probes += 1
                        try:
                            _ = future.result() # Handled internally by _probe_http_https
                        except Exception as e:
                            logger.debug(f"Error during probing for {futures[future]}: {e}")
                        
                        if self.verbose and completed_probes % 50 == 0:
                            live_count = sum(1 for v in self.resolved_subdomains_data.values() if v.get('is_live_http') or v.get('is_live_https'))
                            sys.stdout.write(f"\r [.] Probing Progress: {completed_probes}/{final_resolved_count_at_start} - Verified Live: {live_count}")
                            sys.stdout.flush()
                sys.stdout.write(f"\r[*] Live host probing completed.\n")
                sys.stdout.flush()
            else:
                logger.info("[*] All resolved subdomains already probed or none to probe.")
        else:
            logger.info("[*] Live host verification (probing) is disabled.")

    def phase_port_scanning(self):
        """Performs port scanning if enabled."""
        if self.do_port_scan:
            logger.info("\n--- Phase 4: Port Scanning for Live Hosts ---")
            subdomains_for_port_scan = []
            with self.data_lock:
                # Only scan live ones that haven't been scanned for ports yet
                subdomains_for_port_scan = [
                    d for d, data in self.resolved_subdomains_data.items() 
                    if (data.get('is_live_http') or data.get('is_live_https')) and not data.get('open_ports')
                ]

            if subdomains_for_port_scan:
                logger.info(f"[*] Scanning ports on {len(subdomains_for_port_scan)} live subdomains...")
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self._check_open_ports, name, self.resolved_subdomains_data[name].get('primary_ip')): name 
                               for name in subdomains_for_port_scan}
                    
                    completed_scans = 0
                    final_scan_count_at_start = len(subdomains_for_port_scan)
                    for future in as_completed(futures):
                        completed_scans += 1
                        try:
                            _ = future.result() # Handled internally by _check_open_ports
                        except Exception as e:
                            logger.debug(f"Error during port scanning for {futures[future]}: {e}")

                        if self.verbose and completed_scans % 20 == 0:
                            sys.stdout.write(f"\r [.] Port Scan Progress: {completed_scans}/{final_scan_count_at_start}")
                            sys.stdout.flush()
                sys.stdout.write(f"\r[*] Port scanning completed.\n")
                sys.stdout.flush()
            else:
                logger.info("[*] No live subdomains to scan or all already scanned for ports.")
        else:
            logger.info("[*] Port scanning is disabled.")

    def phase_recursive_enumeration(self):
        """Initiates recursive enumeration if enabled."""
        if self.recursion_depth > 0:
            logger.info(f"\n--- Phase 5: Recursive Enumeration (Max Depth: {self.recursion_depth}) ---")
            self._recursive_enumerate(depth=self.recursion_depth)
        else:
            logger.info("[*] Recursive enumeration is disabled.")

    def phase_final_reporting(self):
        """Generates final reports and outputs."""
        logger.info("\n--- Subdomain Enumeration & Verification Complete ---")

        # Get final counts for report
        total_unique_discovered = len(self.found_subdomains)
        total_dns_resolved = sum(1 for s in self.resolved_subdomains_data if self.resolved_subdomains_data[s].get('is_resolved'))
        live_verified_subdomains = sorted([
            s for s, data in self.resolved_subdomains_data.items() 
            if data.get('is_live_http') or data.get('is_live_https')
        ])
        
        logger.info(f"Summary for {self.domain}:")
        logger.info(f"  Total unique subdomains discovered throughout: {total_unique_discovered}")
        logger.info(f"  Total unique DNS-resolved subdomains: {total_dns_resolved}")
        logger.info(f"  Total unique VERIFIED LIVE subdomains: {len(live_verified_subdomains)}")

        if live_verified_subdomains:
            logger.info("\n--- Verified Live Subdomains Details ---")
            for subd in live_verified_subdomains:
                data = self.resolved_subdomains_data[subd]
                logger.info(f" - {subd}")
                
                # Format IP addresses nicely
                ips = []
                if data.get('ip_v4'): ips.extend(data['ip_v4'])
                if data.get('ip_v6'): ips.extend(data['ip_v6'])
                if ips: logger.info(f"     IP(s): {', '.join(ips)}")

                if data.get('is_live_https'):
                    logger.info(f"     HTTPS: {data['final_url_https']} (Status: {data['live_status_code']})")
                elif data.get('is_live_http'):
                    logger.info(f"     HTTP: {data['final_url_http']} (Status: {data['live_status_code']})")
                
                if data.get('title'): logger.info(f"     Title: {data['title']}")
                if data.get('server_header'): logger.info(f"     Server: {data['server_header']}")
                if data.get('x_powered_by'): logger.info(f"     Powered By: {data['x_powered_by']}")
                
                if data.get('cert_cn'): logger.info(f"     Cert CN: {data['cert_cn']}")
                if data.get('cert_sans'): logger.info(f"     Cert SANs: {', '.join(data['cert_sans'])}")
                
                if data.get('open_ports'): logger.info(f"     Open Ports: {', '.join(map(str, data['open_ports']))}")
                
                # Add other useful info if available
                if data.get('cname'): logger.info(f"     CNAME: {', '.join(data['cname'])}")
                if data.get('mx'): logger.info(f"     MX: {', '.join(data['mx'])}")
                if data.get('ns'): logger.info(f"     NS: {', '.join(data['ns'])}")
                if data.get('txt'): logger.info(f"     TXT: {', '.join(data['txt'])}")

            # Final output to files
            if self.output_file: # Simple list of live resolved domains
                with open(self.output_file, 'w') as f:
                    for subd in live_verified_subdomains:
                        f.write(f"{subd}\n")
                logger.info(f"\nVerified live subdomain list saved to: {self.output_file}")
            
            # JSONL is written incrementally throughout
            if self.output_jsonl_file:
                logger.info(f"Detailed full results (including all resolved, probed, scanned info) saved to: {self.output_jsonl_file}")

            if self.output_csv_file:
                self._export_csv()
        else:
            logger.info(f"No VERIFIED LIVE subdomains found for {self.domain}.")

# --- Main execution block for direct script run ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Militarized Subdomain Enumerator and Verifier (Operation Iron Veil: Hardened & Sharpened)",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for brute-force. "
                                                 "If not provided, a small default will be created.")
    parser.add_argument("-o", "--output", help="Base path for output files (e.g., 'results.txt' will create 'results.jsonl' and 'results.csv').")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent threads (default: 20).")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds for HTTP/S and DNS (default: 10).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (display debug messages).")
    parser.add_argument("-r", "--recursion", type=int, default=0, help="Recursion depth for sub-subdomains (0 for none, max 2 recommended). "
                                                                        "Caution: can significantly increase scan time and network load.")
    parser.add_argument("-p", "--proxies", help="Path to a file containing proxies (e.g., http://user:pass@ip:port), one per line.")
    parser.add_argument("--no-probe", action="store_false", dest="do_probe", help="Disable HTTP/S probing and verification of resolved subdomains.")
    parser.add_argument("--port-scan", action="store_true", dest="do_port_scan", help="Enable basic port scanning on live HTTP/S subdomains for common ports.")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Add a delay between requests *per thread* in seconds (e.g., 0.1 for 100ms delay). "
                                                                       "Helps avoid rate limiting.")
    
    args = parser.parse_args()

    # Set logger level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO) # Default info level for non-verbose

    # --- API Key Management (Example) ---
    # It's recommended to load API keys securely, e.g., from environment variables.
    api_keys_config = {
        'virustotal': os.getenv('VEIL_VT_API_KEY', ''), # Environment var: VEIL_VT_API_KEY
        # 'hackertarget': os.getenv('VEIL_HT_API_KEY', ''),
        # 'shodan': os.getenv('VEIL_SHD_API_KEY', ''),
        # Add more as needed
    }

    # --- Output File Defaulting ---
    if not args.output:
        args.output = f"{args.domain.replace('.', '_')}_recon_results.txt"
        logger.info(f"No output file specified. Defaulting to: {args.output}")

    # --- Wordlist Defaulting ---
    wordlist_path_to_use = args.wordlist
    if not wordlist_path_to_use:
        default_wordlist_name = "default_subdomains_mini.txt"
        if not os.path.exists(default_wordlist_name):
            logger.info("No wordlist provided and default not found. Creating a small default wordlist for quick testing.")
            try:
                with open(default_wordlist_name, "w") as f:
                    f.write("www\nmail\ndev\ntest\napi\nblog\nvpn\nadmin\nwebmail\napp\ncdn\nsftp\ndocs\nportal\n")
            except IOError as e:
                logger.error(f"Could not create default wordlist: {e}. Brute-force will be skipped.")
                wordlist_path_to_use = None
        else:
            logger.info(f"No wordlist provided. Using existing default: {default_wordlist_name}")
        wordlist_path_to_use = default_wordlist_name


    # --- Instantiate and Run the Enumerator ---
    try:
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            wordlist_path=wordlist_path_to_use,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            output_file=args.output,
            api_keys=api_keys_config,
            recursion_depth=args.recursion,
            proxy_list_path=args.proxies,
            do_probe=args.do_probe,
            do_port_scan=args.do_port_scan,
            rate_limit_delay_per_thread=args.rate_limit
        )
        enumerator.run()
    except Exception as e:
        logger.critical(f"An unhandled error occurred during enumeration: {e}", exc_info=True)
        sys.exit(1)
