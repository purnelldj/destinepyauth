"""
destinepyauth - Authentication library for DESP (Destination Earth Service Platform).

This module provides a simple API for authenticating against various DESP services.

Quick Start:
    >>> from destinepyauth import get_token
    >>> token = get_token("highway")  # Interactive prompt for credentials
    >>> # Or with credentials
    >>> token = get_token("highway", username="user@example.com", password="secret")

For services that use .netrc (like CacheB with zarr):
    >>> from destinepyauth import get_token
    >>> token = get_token("cacheb", write_netrc=True)
    >>> # Now zarr/xarray will automatically use credentials from ~/.netrc
"""

import logging

from destinepyauth.api import get_token, list_services
from destinepyauth.authentication import AuthenticationService, TokenResult
from destinepyauth.exceptions import AuthenticationError

__all__ = [
    "get_token",
    "list_services",
    "TokenResult",
    "AuthenticationService",
    "AuthenticationError",
]

# Ensure library doesn't configure logging for the application.
# Applications (including notebooks) should configure logging.
logging.getLogger(__name__).addHandler(logging.NullHandler())
