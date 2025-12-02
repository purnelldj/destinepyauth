"""
Exception classes and error handling utilities for destinepyauth.
"""

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from functools import wraps


class AuthenticationError(Exception):
    """Base exception for authentication errors."""

    pass


def handle_http_errors(error_message: str):
    """
    Decorator to handle common HTTP errors with a custom message.

    Args:
        error_message: Base error message to prepend to specific error details

    Returns:
        Decorated function that raises AuthenticationError on HTTP failures

    Example:
        @handle_http_errors("Failed to fetch data")
        def fetch_data(url):
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Timeout:
                raise AuthenticationError(f"{error_message}: Connection timeout")
            except ConnectionError:
                raise AuthenticationError(f"{error_message}: Connection failed")
            except requests.HTTPError as e:
                status = e.response.status_code if e.response else "unknown"
                raise AuthenticationError(f"{error_message}: HTTP {status}")
            except RequestException as e:
                raise AuthenticationError(f"{error_message}: {e}")

        return wrapper

    return decorator
