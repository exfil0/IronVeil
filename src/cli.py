import argparse
import os
import sys
from ironveil import SubdomainEnumerator
from ironveil.config import logger

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Militarized Subdomain Enumerator and Verifier (Operation Iron Veil: Hardened & Sharpened)",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # (Copy argparse from original)

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    api_keys_config = {
        'virustotal': os.getenv('VEIL_VT_API_KEY', ''),
    }

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
