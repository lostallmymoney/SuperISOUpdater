# utils_network_patch.py

def get_cli_retries():
    import sys
    import argparse
    # Try to parse -r/--retries from sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--retries', default=0)
    args, _ = parser.parse_known_args()
    return args.retries
