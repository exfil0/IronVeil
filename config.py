import os
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests

# Suppress SSL warnings globally
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# User Agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 10; Mobile; rv:90.0) Gecko/90.0 Firefox/90.0',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Common ports for scanning (configurable here)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

# Logger setup (can be customized)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# API keys (loaded from env vars)
def load_api_keys():
    return {
        'virustotal': os.getenv('VEIL_VT_API_KEY', ''),
        # Add more as needed
    }
