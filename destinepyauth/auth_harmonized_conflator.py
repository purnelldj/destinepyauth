#! /usr/bin/env python3

import sys
import argparse

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

    args = parser.parse_args()

    try:
        # Load Config
        config, scope, hook = ConfigurationFactory.load_config(args.SERVICE)

        # Initialize Service
        auth_service = AuthenticationService(config, scope, post_auth_hook=hook)

        # Execute
        auth_service.login()

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
