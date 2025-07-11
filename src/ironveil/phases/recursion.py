from ..config import logger
from ..enumerator import SubdomainEnumerator

def recursive_enumerate(self, depth):
    if depth < 0: return

    candidates_for_recursion = set()
    with self.data_lock:
        for subd_data in list(self.resolved_subdomains_data.values()):
            if not subd_data.get('is_resolved'): continue

            for key in ['cname', 'ns']:
                for target_name in subd_data.get(key, []):
                    if target_name.endswith(self.domain) and target_name.count('.') > self.domain.count('.'):
                        candidates_for_recursion.add(target_name)

            current_domain_str = subd_data['domain']
            if current_domain_str.count('.') > self.domain.count() + 1:
                parts = current_domain_str.split('.')
                potential_new_base = ".".join(parts[1:]) 
                if potential_new_base.endswith(self.domain) and potential_new_base != self.domain:
                    candidates_for_recursion.add(potential_new_base)

    newly_found_in_recursion_cycle = set()
    for base_domain_for_recursion in candidates_for_recursion:
        if base_domain_for_recursion == self.domain: continue 
        
        logger.info(f"[*] Recursing into new base domain: {base_domain_for_recursion} (Depth Remaining: {depth})...")
        recursive_enumerator = SubdomainEnumerator(
            domain=base_domain_for_recursion,
            wordlist_path=self.wordlist_path,
            threads=self.threads // 2 if self.threads > 1 else 1,
            timeout=self.timeout,
            verbose=self.verbose,
            output_file=None,
            api_keys=self.api_keys,
            recursion_depth=0,
            proxy_list_path=self.proxy_list_path,
            do_probe=self.do_probe,
            do_port_scan=self.do_port_scan,
            rate_limit_delay_per_thread=self.rate_limit_delay_per_thread
        )
        recursive_enumerator.run_recursive_phase()

        with self.data_lock:
            for dns_entry, data in recursive_enumerator.resolved_subdomains_data.items():
                if dns_entry.endswith(self.domain) and dns_entry not in self.resolved_subdomains_data:
                    self.resolved_subdomains_data[dns_entry] = data
                    self.found_subdomains.add(dns_entry)
                    newly_found_in_recursion_cycle.add(dns_entry)
                    write_to_output(self, dns_entry, data)

    if newly_found_in_recursion_cycle:
        logger.info(f"[*] Discovered {len(newly_found_in_recursion_cycle)} new subdomains during recursion at depth {depth}.")
        if depth > 1:
            recursive_enumerate(self, depth - 1)
    else:
        logger.info(f"[*] No new subdomains found originating from depth {depth} recursion.")
