from .config import logger, USER_AGENTS, COMMON_PORTS, load_api_keys
from .utils.dns_utils import initialize_dns_resolver, detect_wildcard
from .utils.http_utils import get_session_with_proxy, make_request
from .utils.output_utils import write_to_output, export_csv
from .phases.passive import passive_certsh, passive_hackertarget, passive_virustotal, passive_wayback, passive_bufferover, passive_alienvault, passive_dnsdumpster
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
                     write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
                return None

            # --- Smart Wildcard Filter Check ---
            is_wildcard_false_positive = False
            if self.wildcard_ip_and_content_hash and primary_resolved_ip == self.wildcard_ip_and_content_hash['ip']:
                if self.do_probe:
                    # Probe to differentiate based on content.
                    probe_info = probe_http_https(self, full_domain, primary_resolved_ip, is_wildcard_check=True)
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
                     write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
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
            
            write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain]) # Write initial DNS data
            
            logger.debug(f" [+] Resolved DNS for: {full_domain}")
            return self.resolved_subdomains_data[full_domain] # Return the comprehensive data dict

        except Exception as e:
            logger.error(f" [!] Critical DNS resolution error for {full_domain}: {e}")
            with self.data_lock:
                 self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'resolution_error', 'error_msg': str(e)})
                 write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
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

    @backoff.on_exception(backoff.expo, Exception, max_tries=5, jitter=backoff.full_jitter, logger=logger)
    def _resolve_subdomain(self, subdomain_prefix):
        full_domain = f"{subdomain_prefix}.{self.domain}"
        
        if self.rate_limit_delay_per_thread > 0:
            time.sleep(self.rate_limit_delay_per_thread * random.uniform(0.8, 1.2))

        with self.data_lock:
            if full_domain in self.resolved_subdomains_data and self.resolved_subdomains_data[full_domain].get('is_resolved', False):
                return self.resolved_subdomains_data[full_domain]
            if full_domain not in self.resolved_subdomains_data:
                 self.resolved_subdomains_data[full_domain] = {'domain': full_domain, 'is_resolved': False}

        current_resolver_ip = self.resolvers[0]
        self.dns_resolver.nameservers = [current_resolver_ip]
        
        try:
            resolved_ip_v4 = []
            resolved_ip_v6 = []
            primary_resolved_ip = None

            for rtype in ['A', 'AAAA']:
                try:
                    answers = self.dns_resolver.resolve(full_domain, rtype)
                    if rtype == 'A':
                        resolved_ip_v4 = [str(a) for a in answers]
                    else:
                        resolved_ip_v6 = [str(a) for a in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e: logger.debug(f"Error resolving {rtype} for {full_domain}: {e}")
            
            if resolved_ip_v4: primary_resolved_ip = resolved_ip_v4[0]
            elif resolved_ip_v6: primary_resolved_ip = resolved_ip_v6[0]

            if not primary_resolved_ip:
                with self.data_lock:
                     self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'no_a_aaaa_record'})
                     write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
                return None

            is_wildcard_false_positive = False
            if self.wildcard_ip_and_content_hash and primary_resolved_ip == self.wildcard_ip_and_content_hash['ip']:
                if self.do_probe:
                    probe_info = probe_http_https(self, full_domain, primary_resolved_ip, is_wildcard_check=True)
                    if probe_info and probe_info.get('live_status_code') and probe_info['live_status_code'] < 400:
                        content_hash_match = (probe_info.get('content_hash') == self.wildcard_ip_and_content_hash['content_hash'])
                        title_match = (probe_info.get('title') == self.wildcard_ip_and_content_hash['title'])

                        if content_hash_match or title_match: 
                            is_wildcard_false_positive = True
                            logger.debug(f" [-] Skipping {full_domain} due to wildcard match (IP & content/title).")
                        else:
                            logger.debug(f" [+] {full_domain} resolves to wildcard IP but has UNIQUE content. Keeping.")
                    else:
                        is_wildcard_false_positive = True
                        logger.debug(f" [-] Skipping {full_domain} (Wildcard IP, and no live HTTP/S content).")
                else:
                    is_wildcard_false_positive = True
                    logger.debug(f" [-] Skipping {full_domain} due to wildcard match (IP only, probing disabled).")

            if is_wildcard_false_positive:
                with self.data_lock:
                     self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'wildcard_filtered'})
                     write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
                return None

            all_records = {'A': resolved_ip_v4, 'AAAA': resolved_ip_v6, 'CNAME': [], 'MX': [], 'NS': [], 'TXT': []}
            for rtype in ['CNAME', 'MX', 'NS', 'TXT']:
                try:
                    answers = self.dns_resolver.resolve(full_domain, rtype)
                    all_records[rtype] = [str(a).rstrip('.') for a in answers]
                    
                    for ans in answers:
                        target_sub = None
                        if rtype == 'CNAME' and hasattr(ans, 'target'):
                            target_sub = str(ans.target).rstrip('.')
                        elif rtype == 'MX' and hasattr(ans, 'exchange'):
                            target_sub = str(ans.exchange).rstrip('.')
                        elif rtype == 'NS' and hasattr(ans, 'target'):
                            target_sub = str(ans.target).rstrip('.')
                        
                        if target_sub and target_sub.endswith(self.domain) and target_sub != full_domain:
                            self._add_found(target_sub)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e: logger.debug(f"Error resolving {rtype} for {full_domain}: {e}")

            with self.data_lock:
                self.resolved_subdomains_data[full_domain].update({
                    'is_resolved': True,
                    'ip_v4': all_records['A'], 'ip_v6': all_records['AAAA'],
                    'cname': all_records['CNAME'], 'mx': all_records['MX'], 'ns': all_records['NS'], 'txt': all_records['TXT'],
                    'primary_ip': primary_resolved_ip,
                    'live_status_code': None, 'is_live_http': False, 'is_live_https': False,
                    'title': None, 'server_header': None, 'x_powered_by': None,
                    'content_hash': None, 'cert_cn': None, 'cert_sans': [],
                    'open_ports': []
                })
            
            write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
            
            logger.debug(f" [+] Resolved DNS for: {full_domain}")
            return self.resolved_subdomains_data[full_domain]

        except Exception as e:
            logger.error(f" [!] Critical DNS resolution error for {full_domain}: {e}")
            with self.data_lock:
                 self.resolved_subdomains_data[full_domain].update({'is_resolved': False, 'status': 'resolution_error', 'error_msg': str(e)})
                 write_to_output(self, full_domain, self.resolved_subdomains_data[full_domain])
            raise

        finally:
            self.resolvers.rotate(-1)

    def run(self):
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
        with self.data_lock:
            self.found_subdomains.clear()
            self.resolved_subdomains_data.clear()
        
        self.phase_passive_recon()
        self.phase_active_dns_discovery()
        self.phase_live_host_verification()

    def phase_passive_recon(self):
        logger.info("\n--- Phase 1: Passive Reconnaissance ---")
        passive_certsh(self)
        passive_hackertarget(self)
        passive_virustotal(self)
        passive_wayback(self)
        passive_bufferover(self)
        passive_alienvault(self)
        passive_dnsdumpster(self)
        time.sleep(2)

    def phase_active_dns_discovery(self):
        logger.info("\n--- Phase 2: Active DNS Discovery ---")
        active_brute_force(self)
        active_permutation(self)
        active_zone_transfer(self)

    def phase_live_host_verification(self):
        if self.do_probe:
            logger.info("\n--- Phase 3: Live Host Probing & Verification ---")
            subdomains_to_probe = []
            with self.data_lock:
                subdomains_to_probe = [
                    d for d, data in self.resolved_subdomains_data.items() 
                    if data.get('is_resolved') and not data.get('is_live_http') and not data.get('is_live_https')
                ]
            
            if subdomains_to_probe:
                logger.info(f"[*] Probing {len(subdomains_to_probe)} resolved subdomains...")
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(probe_http_https, self, name, self.resolved_subdomains_data[name].get('primary_ip')): name 
                               for name in subdomains_to_probe}
                    
                    completed_probes = 0
                    final_resolved_count_at_start = len(subdomains_to_probe)
                    for future in as_completed(futures):
                        completed_probes += 1
                        try:
                            _ = future.result()
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
        if self.do_port_scan:
            logger.info("\n--- Phase 4: Port Scanning for Live Hosts ---")
            subdomains_for_port_scan = []
            with self.data_lock:
                subdomains_for_port_scan = [
                    d for d, data in self.resolved_subdomains_data.items() 
                    if (data.get('is_live_http') or data.get('is_live_https')) and not data.get('open_ports')
                ]

            if subdomains_for_port_scan:
                logger.info(f"[*] Scanning ports on {len(subdomains_for_port_scan)} live subdomains...")
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(check_open_ports, self, name, self.resolved_subdomains_data[name].get('primary_ip')): name 
                               for name in subdomains_for_port_scan}
                    
                    completed_scans = 0
                    final_scan_count_at_start = len(subdomains_for_port_scan)
                    for future in as_completed(futures):
                        completed_scans += 1
                        try:
                            _ = future.result()
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
        if self.recursion_depth > 0:
            logger.info(f"\n--- Phase 5: Recursive Enumeration (Max Depth: {self.recursion_depth}) ---")
            recursive_enumerate(self, self.recursion_depth)
        else:
            logger.info("[*] Recursive enumeration is disabled.")

    def phase_final_reporting(self):
        logger.info("\n--- Subdomain Enumeration & Verification Complete ---")

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
                
                if data.get('cname'): logger.info(f"     CNAME: {', '.join(data['cname'])}")
                if data.get('mx'): logger.info(f"     MX: {', '.join(data['mx'])}")
                if data.get('ns'): logger.info(f"     NS: {', '.join(data['ns'])}")
                if data.get('txt'): logger.info(f"     TXT: {', '.join(data['txt'])}")

            if self.output_file:
                with open(self.output_file, 'w') as f:
                    for subd in live_verified_subdomains:
                        f.write(f"{subd}\n")
                logger.info(f"\nVerified live subdomain list saved to: {self.output_file}")
            
            if self.output_jsonl_file:
                logger.info(f"Detailed full results (including all resolved, probed, scanned info) saved to: {self.output_jsonl_file}")

            if self.output_csv_file:
                export_csv(self)
        else:
            logger.info(f"No VERIFIED LIVE subdomains found for {self.domain}.")
