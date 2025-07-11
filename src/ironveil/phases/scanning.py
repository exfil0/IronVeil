from ..config import logger, COMMON_PORTS
import socket
import random
import time
from ..utils.output_utils import write_to_output

def check_open_ports(self, subdomain, ip_address, common_ports=COMMON_PORTS):
    if not ip_address:
         logger.debug(f" [!] No IP provided for port scan of {subdomain}.")
         return
    
    open_ports = []
    for port in common_ports:
        if self.rate_limit_delay_per_thread > 0:
            time.sleep(self.rate_limit_delay_per_thread * random.uniform(0.8, 1.2))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
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
            if subdomain in self.resolved_subdomains_data:
                self.resolved_subdomains_data[subdomain]['open_ports'] = open_ports
            else:
                self.resolved_subdomains_data[subdomain] = {'domain': subdomain, 'open_ports': open_ports}
        write_to_output(self, subdomain, self.resolved_subdomains_data[subdomain])
    
    return open_ports
