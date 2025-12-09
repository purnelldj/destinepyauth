"""
High-level API for DESP authentication.

This module provides simple, user-friendly functions for authenticating
against DESP services without needing to understand the underlying
authentication flow.
"""

import logging
from typing import Optional

from destinepyauth.authentication import AuthenticationService, TokenResult
from destinepyauth.services import ConfigurationFactory, ServiceRegistry


def list_services() -> list[str]:
    """
    List all available service names.

    Returns:
        List of service names that can be used with get_token().

    Example:
        >>> from destinepyauth import list_services
        >>> list_services()
        ['cacheb', 'streamer', 'insula', 'eden', 'dea', 'highway']
    """
    return ServiceRegistry.list_services()


def get_token(
    service: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    write_netrc: bool = False,
    verbose: bool = False,
) -> TokenResult:
    """
    Authenticate and get an access token for a DESP service.

    This is the main entry point for programmatic authentication.
    If username/password are not provided, they will be read from
    environment variables or prompted interactively.

    Args:
        service: Service name (e.g., 'highway', 'cacheb', 'eden', 'insula').
        username: DESP username. If None, uses DESPAUTH_USER env var or prompts.
        password: DESP password. If None, uses DESPAUTH_PASSWORD env var or prompts.
        write_netrc: If True, write/update the token in ~/.netrc file.
        verbose: If True, print logs at DEBUG level.

    Returns:
        TokenResult containing access_token and decoded payload.
        Can be used as a string directly (str(result) returns the token).

    Raises:
        AuthenticationError: If authentication fails.
        ValueError: If service name is not recognized.

    Example:
        >>> from destinepyauth import get_token
        >>>
        >>> # Interactive authentication
        >>> result = get_token("highway")
        >>> token = result.access_token
        >>>
        >>> # Use with requests
        >>> import requests
        >>> headers = {"Authorization": f"Bearer {result.access_token}"}
        >>> response = requests.get(url, headers=headers)
        >>>
        >>> # For zarr/xarray with .netrc support
        >>> result = get_token("cacheb", write_netrc=True)
        >>> import xarray as xr
        >>> ds = xr.open_dataset(url, engine="zarr",
        ...     storage_options={"client_kwargs": {"trust_env": True}})
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
