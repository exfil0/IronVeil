# All passive recon methods here
from ..config import logger
from ..utils.http_utils import make_request
import json
import re
import backoff
from urllib.parse import urlparse

@backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter)
def passive_certsh(self):
    logger.info(f"[*] Running crt.sh passive scan for {self.domain}...")
    url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
    response = self._make_request(url)
    if response:
        try:
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

# (Add other passive methods similarly: passive_hackertarget, passive_virustotal, etc., from the original code)
