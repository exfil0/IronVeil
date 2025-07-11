from ..config import logger
import dns.resolver
import random
import time
from ..phases.probing import probe_http_https

def initialize_dns_resolver(self):
    self.dns_resolver = dns.resolver.Resolver()
    self.dns_resolver.timeout = self.timeout / 2
    self.dns_resolver.lifetime = self.timeout
    if self.resolvers:
        self.dns_resolver.nameservers = [self.resolvers[0]]
    else:
        logger.error("No DNS resolvers configured! DNS resolution will fail.")

def detect_wildcard(self):
    random_sub_prefix = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=15))}-{int(time.time())}"
    random_full_domain = f"{random_sub_prefix}.{self.domain}"
    
    resolved_ip = None
    try:
        a_answers = self.dns_resolver.resolve(random_full_domain, 'A')
        resolved_ip = str(a_answers[0])
        logger.info(f" [!] Potentially detected wildcard IP for {self.domain}: {resolved_ip}.")
    except Exception:
        logger.debug(f" [.] No A record for random subdomain {random_full_domain}. No wildcard IP detected so far.")
        return None

    if resolved_ip and self.do_probe:
        try:
            probe_info = probe_http_https(self, random_full_domain, resolved_ip, is_wildcard_check=True)
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
    
    return {'ip': resolved_ip, 'content_hash': None, 'title': None} if resolved_ip else None
