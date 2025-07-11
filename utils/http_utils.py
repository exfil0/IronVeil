from ..config import USER_AGENTS
import random
import requests
import backoff

def get_session_with_proxy(self):
    session = requests.Session()
    session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    
    proxy_url = random.choice(self.proxies)
    if proxy_url:
        session.proxies = {'http': proxy_url, 'https': proxy_url}
    
    return session

@backoff.on_exception(backoff.expo, requests.exceptions.RequestException, max_tries=5, jitter=backoff.full_jitter)
def make_request(self, url, method="GET", json_data=None, data=None, headers=None, allow_redirects=True):
    session = self._get_session_with_proxy()
    req_headers = session.headers.copy()
    if headers:
        req_headers.update(headers)
    
    # Introduce per-thread delay if configured
    if self.rate_limit_delay_per_thread > 0:
        time.sleep(self.rate_limit_delay_per_thread * random.uniform(0.8, 1.2))

    response = session.request(method, url, json=json_data, data=data, timeout=self.timeout, headers=req_headers, allow_redirects=allow_redirects)
    response.raise_for_status()
    return response
