#! /usr/bin/env python3

import sys
import argparse
import logging

from destinepyauth.services import ConfigurationFactory
from destinepyauth.authentication import AuthenticationService


def main():
    parser = argparse.ArgumentParser(description="Get token from desp iam.")

    parser.add_argument(
        "--SERVICE",
        "-s",
        required=True,
        type=str,
        help="Service name (e.g. 'streamer', 'cacheb', 'highway', etc.)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        # Load Config
        config, scope, hook = ConfigurationFactory.load_config(args.SERVICE)

        # Initialize Service
        auth_service = AuthenticationService(config, scope, post_auth_hook=hook)

        # Execute
        auth_service.login()

    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
