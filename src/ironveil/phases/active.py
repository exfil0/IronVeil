from ..config import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import random
import re
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import backoff
import os

def active_brute_force(self):
    if not self.wordlist_path:
        logger.info("[!] No wordlist path provided for brute-force. Skipping.")
        return

    logger.info(f"[*] Running brute-force scan for {self.domain} using {self.wordlist_path}...")
    subdomain_prefixes = []
    try:
        with open(self.wordlist_path, 'r') as f:
            with self.data_lock:
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
                _ = future.result()
            except Exception as e:
                logger.debug(f" [!] Error during brute-force for {futures[future]}: {e}")
            
            if self.verbose and completed_tasks % 50 == 0:
                current_resolved_count = sum(1 for s in self.resolved_subdomains_data if self.resolved_subdomains_data[s].get('is_resolved'))
                progress = (completed_tasks / total_tasks) * 100
                sys.stdout.write(f"\r [.] Brute-force Progress: {progress:.2f}% ({completed_tasks}/{total_tasks}) - Resolved: {current_resolved_count}")
                sys.stdout.flush()
    sys.stdout.write(f"\r[*] Brute-force completed. Total subdomains discovered: {len(self.found_subdomains)}.\n")
    sys.stdout.flush()

def active_permutation(self):
    if not self.found_subdomains:
        logger.info("[!] No initial subdomains found for permutation generation. Skipping.")
        return

    logger.info(f"[*] Generating and resolving advanced permutations...")
    permutation_attempts = set()
    
    common_parts = [
        'dev', 'test', 'stage', 'qa', 'int', 'preprod', 'uat', 'dr', 'new', 'old', 'beta', 'alpha',
        'api', 'admin', 'auth', 'cdn', 'mail', 'webmail', 'ftp', 'docs', 'app', 'portal', 'secure',
        'dashboard', 'manage', 'support', 'status', 'vpn', 'proxy', 'store', 'shop', 'blog', 'news',
        'img', 'stats', 'login', 'sso', 'static', 'assets', 'internal',
        '01', '02', '03', '1', '2', '3',
    ]
    dev_suffixes = ["-dev", "-test", "-stage"]
    subs_map = {'a': 's', 's': 'a', 'o': 'p', 'p': 'o', 'l': 'k', 'k': 'l'}

    with self.data_lock:
        initial_subdomains_for_permuting = list(self.found_subdomains)

    for subdomain_full in initial_subdomains_for_permuting:
        try:
            base_prefix = subdomain_full.replace(f".{self.domain}", "")
            if base_prefix == "": continue
        except ValueError: continue

        for part in common_parts:
            permutation_attempts.add(f"{part}.{base_prefix}")
            permutation_attempts.add(f"{base_prefix}-{part}")
            permutation_attempts.add(f"{part}-{base_prefix}")
            permutation_attempts.add(f"{base_prefix}{part}")
            permutation_attempts.add(f"{part}{base_prefix}")

        if len(base_prefix) > 1:
            for i in range(len(base_prefix) - 1):
                typo_prefix = list(base_prefix)
                typo_prefix[i], typo_prefix[i+1] = typo_prefix[i+1], typo_prefix[i]
                permutation_attempts.add(''.join(typo_prefix))

        for sfx in dev_suffixes:
             if sfx in base_prefix:
                 permutation_attempts.add(base_prefix.replace(sfx, ''))
             else:
                 permutation_attempts.add(f"{base_prefix}{sfx}")

        num_match = re.search(r'([a-zA-Z]+)(\d+)$', base_prefix)
        if num_match:
            alpha_part = num_match.group(1)
            num_part = int(num_match.group(2))
            num_len = len(num_match.group(2))
            for i in range(max(1, num_part - 5), num_part + 6):
                permutation_attempts.add(f"{alpha_part}{i:0{num_len}d}")

        for i in range(len(base_prefix)):
            omission = base_prefix[:i] + base_prefix[i+1:]
            if omission: permutation_attempts.add(omission)

        for i in range(len(base_prefix)):
            repetition = base_prefix[:i] + base_prefix[i] + base_prefix[i:]
            permutation_attempts.add(repetition)

        for i, char in enumerate(base_prefix):
            if char in subs_map:
                sub = list(base_prefix)
                sub[i] = subs_map[char]
                permutation_attempts.add(''.join(sub))

    with self.data_lock:
        permutations_to_check = {p for p in permutation_attempts if f"{p}.{self.domain}" not in self.resolved_subdomains_data}
    
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
                _ = future.result()
            except Exception as e:
                logger.debug(f" [!] Error during permutation resolution for {futures[future]}: {e}")
            
            if self.verbose and completed_tasks % 100 == 0:
                current_resolved_count = sum(1 for s in self.resolved_subdomains_data if self.resolved_subdomains_data[s].get('is_resolved'))
                progress = (completed_tasks / total_tasks) * 100
                sys.stdout.write(f"\r [.] Permutation Progress: {progress:.2f}% ({completed_tasks}/{total_tasks}) - Resolved: {current_resolved_count}")
                sys.stdout.flush()
    sys.stdout.write(f"\r[*] Permutation scan completed. Total subdomains discovered: {len(self.found_subdomains)}.\n")
    sys.stdout.flush()

@backoff.on_exception(backoff.expo, Exception, max_tries=3, jitter=backoff.full_jitter, logger=logger)
def active_zone_transfer(self):
    logger.info(f"[*] Attempting DNS Zone Transfer (AXFR) for {self.domain}...")
    try:
        ns_answers = self.dns_resolver.resolve(self.domain, 'NS')
        nameservers = [str(ns.target) for ns in ns_answers]

        for ns_domain in nameservers:
            try:
                ns_ip = str(self.dns_resolver.resolve(ns_domain, 'A')[0])
                transfer_resolver = dns.resolver.Resolver()
                transfer_resolver.nameservers = [ns_ip]
                transfer_resolver.timeout = self.timeout
                transfer_resolver.lifetime = self.timeout
                
                logger.debug(f" [.] Attempting AXFR from {ns_domain} ({ns_ip})...")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, relativize=False, timeout=self.timeout))
                
                for name, node in zone.nodes.items():
                    full_name = str(name).rstrip('.')
                    if full_name.endswith(self.domain):
                       self._add_found(full_name)
                logger.warning(f" [!!!] Zone transfer successful from {ns_domain}! This is a significant finding.")
                return
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
