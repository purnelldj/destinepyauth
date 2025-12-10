"""High-level API for DESP authentication."""

import logging
from typing import Optional

from destinepyauth.authentication import AuthenticationService, TokenResult
from destinepyauth.services import ConfigurationFactory


def get_token(
    service: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    write_netrc: bool = False,
    verbose: bool = False,
) -> TokenResult:
    """
    Authenticate and get an access token for a DESP service.

    Args:
        service: Service name (e.g., 'highway', 'cacheb', 'eden').
        username: DESP username. If None, uses env var or prompts.
        password: DESP password. If None, uses env var or prompts.
        write_netrc: If True, write/update the token in ~/.netrc file.
        verbose: If True, enable DEBUG logging.

    Returns:
        TokenResult containing access_token and decoded payload.

    Raises:
        AuthenticationError: If authentication fails.
        ValueError: If service name is not recognized.
    """
    # Configure only the library logger (do not change the root logger).
    # Applications (including notebooks) should configure handlers.
    log_level = logging.INFO if not verbose else logging.DEBUG
    logging.getLogger("destinepyauth").setLevel(log_level)

    # Load configuration for the service
    config, scope, hook = ConfigurationFactory.load_config(service)

    # Override credentials if provided
    if username:
        config.user = username
    if password:
        config.password = password

    # Create and run authentication
    auth_service = AuthenticationService(
        config=config,
        scope=scope,
        post_auth_hook=hook,
    )

    return auth_service.login(write_netrc=write_netrc)
