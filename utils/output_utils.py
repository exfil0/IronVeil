import json
import csv
from ..config import logger

def write_to_output(self, subdomain, data):
    if self.output_jsonl_file:
        try:
            with self.data_lock:
                with open(self.output_jsonl_file, 'a') as f:
                    f.write(json.dumps(data) + '\n')
        except Exception as e:
            logger.error(f" [!] Error writing to JSONL output for {subdomain}: {e}")

def export_csv(self):
    if not self.output_csv_file: return
    
    logger.info(f"[*] Exporting detailed data to CSV: {self.output_csv_file}")
    
    headers = [
        'domain', 'is_resolved', 'primary_ip', 'ip_v4', 'ip_v6', 'cname', 'mx', 'ns', 'txt',
        'is_live_http', 'is_live_https', 'live_status_code', 'final_url_http', 'final_url_https',
        'title', 'server_header', 'x_powered_by', 'content_hash',
        'cert_cn', 'cert_sans', 'open_ports', 'status', 'error_msg'
    ]
    
    with open(self.output_csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        
        with self.data_lock:
            for domain, data in self.resolved_subdomains_data.items():
                row = {}
                for h in headers:
                    val = data.get(h, '')
                    if isinstance(val, list):
                        row[h] = ', '.join(map(str, val))
                    else:
                        row[h] = val
                writer.writerow(row)
    logger.info(f"[*] CSV export complete to {self.output_csv_file}")
