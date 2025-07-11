from ..config import logger
import re
import hashlib
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import requests

def probe_http_https(self, subdomain_to_probe, ip_address, is_wildcard_check=False):
    probe_results = {
        'live_status_code': None, 'is_live_http': False, 'is_live_https': False,
        'final_url_http': None, 'final_url_https': None,
        'server_header': None, 'x_powered_by': None, 'title': None, 'content_hash': None,
        'cert_cn': None, 'cert_sans': []
    }

    # --- HTTPS Probe ---
    try:
        session = get_session_with_proxy(self)
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
            cert_pem = ssl.get_server_certificate((ip_address, 443)) 
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr: probe_results['cert_cn'] = cn_attr[0].value
            
            try:
                alt_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for entry in alt_names.value.get_values_for_type(x509.DNSName):
                    probe_results['cert_sans'].append(entry)
                    if entry.endswith(self.domain) and entry not in self.found_subdomains:
                        self._add_found(entry) 
            except x509.ExtensionNotFound: pass
            except Exception as e: logger.debug(f"Error parsing SANs for {subdomain_to_probe}: {e}")

        except Exception as e:
            logger.debug(f"Error fetching/parsing cert for {subdomain_to_probe}: {e}")
        
        logger.debug(f" [+] HTTPS live: {subdomain_to_probe} (Status: {response.status_code})")

    except (requests.exceptions.SSLError, ssl.SSLError) as e:
        logger.debug(f" [!] HTTPS SSL error for {subdomain_to_probe}. Trying HTTP. Error: {e}")
    except requests.exceptions.HTTPError as e:
        probe_results['live_status_code'] = e.response.status_code
        logger.debug(f" [!] HTTPS HTTPError for {subdomain_to_probe}: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.debug(f" [!] HTTPS probe failed for {subdomain_to_probe}: {type(e).__name__} - {e}")
    except Exception as e:
        logger.debug(f" [!] Unknown error during HTTPS probe for {subdomain_to_probe}: {e}")

    if is_wildcard_check or not probe_results['is_live_https']: 
        try:
            session = get_session_with_proxy(self)
            response = session.get(f"http://{subdomain_to_probe}", timeout=self.timeout, allow_redirects=True)
            response.raise_for_status()
            
            probe_results['is_live_http'] = True
            if not probe_results['is_live_https']:
                probe_results['live_status_code'] = response.status_code
            probe_results['final_url_http'] = response.url

            if not probe_results['server_header']: probe_results['server_header'] = response.headers.get('Server')
            if not probe_results['x_powered_by']: probe_results['x_powered_by'] = response.headers.get('X-Powered-By')
            if not probe_results['title']:
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                if title_match: probe_results['title'] = title_match.group(1).strip()
            if not probe_results['content_hash']: probe_results['content_hash'] = hashlib.sha256(response.content[:8192]).hexdigest()

            logger.debug(f" [+] HTTP live: {subdomain_to_probe} (Status: {response.status_code})")

        except requests.exceptions.HTTPError as e:
            if not probe_results['is_live_https']:
                probe_results['live_status_code'] = e.response.status_code
            logger.debug(f" [!] HTTP HTTPError for {subdomain_to_probe}: {e.response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.debug(f" [!] HTTP probe failed for {subdomain_to_probe}: {type(e).__name__} - {e}")
        except Exception as e:
            logger.debug(f" [!] Unknown error during HTTP probe for {subdomain_to_probe}: {e}")

    if not is_wildcard_check:
        with self.data_lock:
             current_data = self.resolved_subdomains_data.get(subdomain_to_probe, {'domain': subdomain_to_probe, 'is_resolved': False})
             current_data.update(probe_results)
             self.resolved_subdomains_data[subdomain_to_probe] = current_data
        write_to_output(self, subdomain_to_probe, self.resolved_subdomains_data[subdomain_to_probe])
    
    return probe_results
