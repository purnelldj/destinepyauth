#!/usr/bin/env python3
"""
Command-line interface for DESP authentication.

Usage:
    auth --SERVICE <service_name> [--output <format>] [--verbose]

Examples:
    auth --SERVICE eden                    # Get Eden token (legacy format)
    auth --SERVICE highway --output token  # Get Highway token (just token)
    auth --SERVICE cacheb --output json    # Get CacheB token (full JSON)
"""

import sys
import argparse
import logging
from destinepyauth.services import ConfigurationFactory, ServiceRegistry
from destinepyauth.authentication import AuthenticationService
from destinepyauth.exceptions import AuthenticationError


def main() -> None:
    """
    Main entry point for the authentication CLI.

    Parses command-line arguments, loads service configuration,
    and executes the authentication flow.
    """
    parser = argparse.ArgumentParser(
        description="Get authentication token from DESP IAM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available services: {', '.join(ServiceRegistry.list_services())}",
    )

    parser.add_argument(
        "--SERVICE",
        "-s",
        required=True,
        type=str,
        choices=ServiceRegistry.list_services(),
        help="Service name to authenticate against",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        choices=["json", "token", "legacy"],
        default="legacy",
        help="Output format: 'json' (full JSON), 'token' (just token), 'legacy' (git credential format)",
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
        # Load configuration
        config, scope, hook = ConfigurationFactory.load_config(args.SERVICE)

        # Initialize and execute authentication
        auth_service = AuthenticationService(
            config=config,
            scope=scope,
            post_auth_hook=hook,
            output_format=args.output,
        )
        auth_service.login()

    except AuthenticationError as e:
        logging.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logging.error("Authentication cancelled")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
