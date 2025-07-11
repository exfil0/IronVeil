import argparse
import os
import sys
from ironveil.enumerator import SubdomainEnumerator
from ironveil.config import logger, load_api_keys

def main():
    parser = argparse.ArgumentParser(description="Militarized Subdomain Enumerator and Verifier (Operation Iron Veil: Hardened & Sharpened)",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for brute-force. "
                                                 "If not provided, a small default will be created.")
    parser.add_argument("-o", "--output", help="Base path for output files (e.g., 'results.txt' will create 'results.jsonl' and 'results.csv').")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent threads (default: 20).")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds for HTTP/S and DNS (default: 10).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (display debug messages).")
    parser.add_argument("-r", "--recursion", type=int, default=0, help="Recursion depth for sub-subdomains (0 for none, max 2 recommended). "
                                                                        "Caution: can significantly increase scan time and network load.")
    parser.add_argument("-p", "--proxies", help="Path to a file containing proxies (e.g., http://user:pass@ip:port), one per line.")
    parser.add_argument("--no-probe", action="store_false", dest="do_probe", help="Disable HTTP/S probing and verification of resolved subdomains.", default=True)
    parser.add_argument("--port-scan", action="store_true", dest="do_port_scan", help="Enable basic port scanning on live HTTP/S subdomains for common ports.")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Add a delay between requests *per thread* in seconds (e.g., 0.1 for 100ms delay). "
                                                                       "Helps avoid rate limiting.")
    
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    api_keys_config = load_api_keys()

    if not args.output:
        args.output = f"{args.domain.replace('.', '_')}_recon_results.txt"
        logger.info(f"No output file specified. Defaulting to: {args.output}")

    wordlist_path_to_use = args.wordlist
    if not wordlist_path_to_use:
        default_wordlist_name = "default_subdomains_mini.txt"
        if not os.path.exists(default_wordlist_name):
            logger.info("No wordlist provided and default not found. Creating a small default wordlist for quick testing.")
            try:
                with open(default_wordlist_name, "w") as f:
                    f.write("www\nmail\ndev\ntest\napi\nblog\nvpn\nadmin\nwebmail\napp\ncdn\nsftp\ndocs\nportal\n")
            except IOError as e:
                logger.error(f"Could not create default wordlist: {e}. Brute-force will be skipped.")
                wordlist_path_to_use = None
        else:
            logger.info(f"No wordlist provided. Using existing default: {default_wordlist_name}")
        wordlist_path_to_use = default_wordlist_name

    try:
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            wordlist_path=wordlist_path_to_use,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            output_file=args.output,
            api_keys=api_keys_config,
            recursion_depth=args.recursion,
            proxy_list_path=args.proxies,
            do_probe=args.do_probe,
            do_port_scan=args.do_port_scan,
            rate_limit_delay_per_thread=args.rate_limit
        )
        enumerator.run()
    except Exception as e:
        logger.critical(f"An unhandled error occurred during enumeration: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
