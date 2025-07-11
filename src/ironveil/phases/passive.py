from ..config import logger
from ..utils.http_utils import make_request
import json
import re
import backoff
from urllib.parse import urlparse

@backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
def passive_certsh(self):
    logger.info(f"[*] Running crt.sh passive scan for {self.domain}...")
    url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
    response = make_request(self, url)
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

@backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
def passive_hackertarget(self):
    logger.info(f"[*] Running hackertarget.com passive scan for {self.domain}...")
    url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
    response = make_request(self, url)
    if response:
        for line in response.text.splitlines():
            parts = line.split(',')
            if len(parts) > 0:
                self._add_found(parts[0])
    logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from hackertarget.com.")

@backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=3, jitter=backoff.full_jitter, logger=logger)
def passive_virustotal(self):
    logger.info(f"[*] Running VirusTotal passive scan for {self.domain}...")
    api_key = self.api_keys.get('virustotal')
    if not api_key:
        logger.warning(" [!] No VirusTotal API key provided. Skipping VirusTotal scan.")
        return

    url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
    headers = get_session_with_proxy(self).headers # Get a fresh set of headers
    headers['x-apikey'] = api_key
    
    response = make_request(self, url, headers=headers)
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
    logger.info(f"[*] Running Wayback Machine passive scan for {self.domain}...")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
    response = make_request(self, url)
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
    logger.info(f"[*] Running BufferOver.run passive scan for {self.domain}...")
    url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
    response = make_request(self, url)
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
    logger.info(f"[*] Running AlienVault OTX passive scan for {self.domain}...")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
    response = make_request(self, url)
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
    logger.info(f"[*] Running DNSdumpster.com passive scan for {self.domain}...")
    url = "https://dnsdumpster.com/"
    try:
        response = make_request(self, url)
        csrftoken_match = re.search(r"name='csrfmiddlewaretoken' value='(.*?)'", response.text)
        if not csrftoken_match:
            raise ValueError("CSRF token not found. DNSdumpster.com site structure may have changed.")
        csrftoken = csrftoken_match.group(1)
        
        data = {
            'csrfmiddlewaretoken': csrftoken,
            'targetip': self.domain,
        }
        
        headers = get_session_with_proxy(self).headers # Fresh headers
        headers['Referer'] = url # Important for DNSdumpster
        
        response = make_request(self, url, method="POST", data=data, headers=headers)
        # Extract hostnames from the results table
        host_regex = re.compile(r'<td class="col-md-4">([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')</td>')
        for match in host_regex.finditer(response.text):
            self._add_found(match.group(1))
        
    except (requests.exceptions.RequestException, AttributeError, ValueError) as e:
        logger.error(f" [!] Error fetching from DNSdumpster.com: {e}. Site may have changed or blocked the request.")
    logger.info(f"[*] Discovered {len(self.found_subdomains)} subdomains so far from DNSdumpster.")
