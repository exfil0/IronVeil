# Operation Iron Veil: Hardened & Sharpened Subdomain Enumerator

**Operation Iron Veil** is a comprehensive, militarized subdomain enumeration and verification tool built in Python. It combines passive reconnaissance from multiple OSINT sources, active DNS brute-forcing and permutation generation, HTTP/S probing for live verification, certificate SAN extraction for additional discovery, basic port scanning, and recursive sub-subdomain enumeration. Designed for security researchers, penetration testers, and bug bounty hunters, it maximizes subdomain discovery while minimizing false positives through smart wildcard filtering (IP and content-based).

The tool is multi-threaded for efficiency, resilient with backoff retries, and configurable via CLI flags. It supports proxy rotation for stealth, rate limiting to avoid detection, and outputs in TXT (live subdomains), JSONL (detailed data), and CSV (structured export).

**Key Goals:**
- Discover as many subdomains as possible "without missing any" (though complete enumeration is impossible due to private DNS, etc.).
- Verify live hosts with HTTP/S probes and extract fingerprints (titles, servers, certs).
- Ethical use only: Always obtain permission before scanning.

## Features

- **Passive Recon Sources:** crt.sh, HackerTarget, VirusTotal (API key optional), Wayback Machine, BufferOver.run, AlienVault OTX, DNSdumpster.
- **Active Discovery:** Brute-force with wordlists, permutation generation (prefix/suffix, typos, numbers), zone transfer attempts.
- **Wildcard Filtering:** IP and content/title hashing to reduce false positives from wildcard DNS configs.
- **Live Verification:** HTTP/S probing for status, redirects, titles, headers, content hashes, and TLS cert SANs/CN (discovers more subs).
- **Port Scanning:** Optional quick check on common ports for live hosts.
- **Recursion:** Depth-limited sub-subdomain enumeration based on CNAME/NS or multi-level subs.
- **Resilience & Stealth:** Proxy support, UA rotation, resolver rotation, backoff retries with jitter, configurable rate limiting.
- **Outputs:** TXT (live subs), JSONL (incremental detailed data), CSV (structured with all fields).
- **Thread Safety:** Locks for shared data, efficient concurrency.

## Dependencies

Install required Python packages:
```
pip install requests dnspython backoff cryptography
```

- **dnspython:** For DNS resolution and zone transfers.
- **requests:** For HTTP/S probing and API calls.
- **backoff:** For exponential backoff retries.
- **cryptography:** For TLS cert parsing (SAN/CN extraction).

Standard libraries (no install needed): re, time, json, random, collections, sys, threading, urllib.parse, os, hashlib, socket, logging, ssl, csv.

Note: No internet access required beyond APIs/web; no additional pip installs during runtime.

## Usage

Run the script via CLI with `python script.py [options]`. Required: `--domain`.

### CLI Options
```
usage: script.py [-h] -d DOMAIN [-w WORDLIST] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [-v] [-r RECURSION] [-p PROXIES] [--no-probe] [--port-scan] [--rate-limit RATE_LIMIT]

Militarized Subdomain Enumerator and Verifier (Operation Iron Veil: Hardened & Sharpened)

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain (e.g., example.com)
  -w WORDLIST, --wordlist WORDLIST
                        Path to wordlist for brute-force. If not provided, a small default will be created.
  -o OUTPUT, --output OUTPUT
                        Base path for output files (e.g., 'results.txt' will create 'results.jsonl' and 'results.csv').
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 20).
  --timeout TIMEOUT     Request timeout in seconds for HTTP/S and DNS (default: 10).
  -v, --verbose         Enable verbose logging (display debug messages).
  -r RECURSION, --recursion RECURSION
                        Recursion depth for sub-subdomains (0 for none, max 2 recommended). Caution: can significantly increase scan time and network load.
  -p PROXIES, --proxies PROXIES
                        Path to a file containing proxies (e.g., http://user:pass@ip:port), one per line.
  --no-probe            Disable HTTP/S probing and verification of resolved subdomains.
  --port-scan           Enable basic port scanning on live HTTP/S subdomains for common ports.
  --rate-limit RATE_LIMIT
                        Add a delay between requests *per thread* in seconds (e.g., 0.1 for 100ms delay). Helps avoid rate limiting.
```

### Examples

1. **Basic Scan (Passive + Brute-Force):**
   ```
   python script.py -d example.com -w subdomains.txt -v
   ```
   - Uses default wordlist if not provided.
   - Verbose mode for detailed logs.

2. **Full Scan with Probing, Port Scan, and Recursion:**
   ```
   python script.py -d example.com -w subdomains-top1million.txt -o results.txt -r 1 --port-scan --rate-limit 0.2 -p proxies.txt
   ```
   - Enables recursion (depth 1), port scanning, 200ms delay per thread, proxies.
   - Outputs: results.txt (live subs), results.jsonl (detailed), results.csv (structured).

3. **Passive-Only (No Active/Probe):**
   ```
   python script.py -d example.com --no-probe
   ```
   - Quick, stealthy recon from OSINT sources.

4. **With VirusTotal API (Set Env Var):**
   ```
   export VEIL_VT_API_KEY=your_key_here
   python script.py -d example.com
   ```

## API Keys
Set environment variables for optional APIs:
- `VEIL_VT_API_KEY`: VirusTotal (passive_virustotal).

Add more in `api_keys_config` if extending sources.

## Ethical Considerations
- **Legal Use Only:** Subdomain enumeration can be seen as reconnaissance. Obtain explicit permission before scanning third-party domains. Active probing/port scanning may trigger alerts or violate terms.
- **Rate Limiting:** Use `--rate-limit` to respect API/DNS limits.
- **Proxies:** For anonymity, but ensure ethical sourcing.
- **No Guarantees:** "Without missing any" is aspirational—private subdomains can't be found publicly.

## Limitations & Future Improvements
- IPv6 probing/port scan not fully supported (focuses on IPv4 primary IP).
- No tech fingerprinting/vuln checks (e.g., Wappalyzer, CVE lookup).
- Extend passive sources (e.g., Shodan with key).
- Screenshots or advanced media analysis not included.

Contributions welcome! Report issues or suggest features.

## License
MIT License. Use at your own risk.
