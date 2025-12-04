"""
Main authentication service for DESP OAuth2 authentication flows.
"""

import getpass
import json
import logging
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from typing import Tuple, Optional, Callable, Dict, Any
from dataclasses import dataclass

import requests
from lxml import html
from lxml.etree import ParserError

from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError

from destinepyauth.configs import BaseConfig
from destinepyauth.exceptions import AuthenticationError, handle_http_errors

logger = logging.getLogger(__name__)


@dataclass
class TokenResult:
    """Result of an authentication operation."""

    access_token: str
    """The access token string."""

    decoded: Optional[Dict[str, Any]] = None
    """Decoded token payload (if verification succeeded)."""

    def __str__(self) -> str:
        return self.access_token


class AuthenticationService:
    """
    Service for handling DESP OAuth2 authentication flows.

    Supports the full OAuth2 authorization code flow including:
    - OIDC endpoint discovery via keycloak-python
    - Interactive or configured credential handling
    - Resource owner password credentials grant
    - Token verification and decoding (handled by keycloak-python)
    - Post-authentication hooks (e.g., token exchange)
    - Optional .netrc file management

    Attributes:
        config: Service configuration containing IAM endpoints and credentials.
        scope: OAuth2 scope string for the authorization request.
        post_auth_hook: Optional callback for post-authentication processing.
        netrc_host: Optional hostname for .netrc entry (extracted from redirect_uri if not provided).
    """

    def __init__(
        self,
        config: BaseConfig,
        scope: str,
        post_auth_hook: Optional[Callable[[str, BaseConfig], str]] = None,
        netrc_host: Optional[str] = None,
    ) -> None:
        """
        Initialize the authentication service.

        Args:
            config: Configuration containing IAM URL, realm, client, and credentials.
            scope: OAuth2 scope string (e.g., 'openid', 'openid offline_access').
            post_auth_hook: Optional callable for post-auth token processing.
            netrc_host: Hostname for .netrc entry. If None, extracted from redirect_uri.
        """
        self.config = config
        self.scope = scope
        self.post_auth_hook = post_auth_hook
        self.decoded_token: Optional[Dict[str, Any]] = None
        self.session = requests.Session()
        self.jwks_uri: Optional[str] = None

        # Initialize KeycloakOpenID client
        try:
            self.keycloak_client = KeycloakOpenID(
                server_url=self.config.iam_url,
                client_id=self.config.iam_client,
                realm_name=self.config.iam_realm,
            )
        except KeycloakError as e:
            raise AuthenticationError(f"Failed to initialize Keycloak client: {e}")

        # Extract netrc host from redirect_uri if not provided
        if netrc_host:
            self.netrc_host = netrc_host
        elif config.iam_redirect_uri:
            self.netrc_host = urlparse(config.iam_redirect_uri).netloc
        else:
            self.netrc_host = None

        # Extract netrc host from redirect_uri if not provided
        if netrc_host:
            self.netrc_host = netrc_host
        elif config.iam_redirect_uri:
            self.netrc_host = urlparse(config.iam_redirect_uri).netloc
        else:
            self.netrc_host = None

        logger.debug("Configuration loaded:")
        logger.debug(f"  IAM URL: {self.config.iam_url}")
        logger.debug(f"  IAM Realm: {self.config.iam_realm}")
        logger.debug(f"  IAM Client: {self.config.iam_client}")
        logger.debug(f"  Redirect URI: {self.config.iam_redirect_uri}")
        logger.debug(f"  Scope: {self.scope}")
        logger.debug(f"  Netrc Host: {self.netrc_host}")

    def _get_credentials(self) -> Tuple[str, str]:
        """
        Retrieve user credentials from config or interactive prompt.

        Returns:
            Tuple of (username, password).
        """
        user = self.config.user if self.config.user else input("Username: ")
        password = self.config.password if self.config.password else getpass.getpass("Password: ")
        return user, password

    @handle_http_errors("Failed to discover OIDC endpoints")
    def _discover_endpoints(self) -> None:
        discovery_url = (
            f"{self.config.iam_url}/realms/{self.config.iam_realm}/.well-known/openid-configuration"
        )
        resp = self.session.get(discovery_url, timeout=10)
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
        self.jwks_uri = data.get("jwks_uri")

    @handle_http_errors("Failed to get login page")
    def _get_auth_url_action(self) -> str:
        auth_endpoint = f"{self.config.iam_url}/realms/{self.config.iam_realm}/protocol/openid-connect/auth"
        params: Dict[str, str] = {
            "client_id": self.config.iam_client,
            "redirect_uri": self.config.iam_redirect_uri,
            "scope": self.scope,
            "response_type": "code",
        }

        response = self.session.get(url=auth_endpoint, params=params, timeout=10)
        response.raise_for_status()

        try:
            tree = html.fromstring(response.content.decode())
            forms = tree.forms
            if not forms:
                raise AuthenticationError("No login form found in response")
            return str(forms[0].action)
        except (ParserError, AttributeError) as e:
            raise AuthenticationError(f"Failed to parse login page: {e}")

    @handle_http_errors("Failed to submit credentials")
    def _perform_login(self, auth_url_action: str, user: str, passw: str) -> requests.Response:
        return self.session.post(
            auth_url_action,
            data={"username": user, "password": passw},
            allow_redirects=False,
            timeout=10,
        )

    def _extract_auth_code(self, login_response: requests.Response) -> str:
        if login_response.status_code == 200:
            try:
                tree = html.fromstring(login_response.content)
                error_msg = tree.xpath('//span[@id="input-error"]/text()')
                if error_msg:
                    raise AuthenticationError(f"Login failed: {error_msg[0].strip()}")
            except AuthenticationError:
                raise
            except Exception:
                pass
            raise AuthenticationError("Login failed: Invalid credentials")

        if login_response.status_code != 302:
            raise AuthenticationError(f"Login failed: Unexpected status {login_response.status_code}")

        location = login_response.headers.get("Location", "")
        parsed = parse_qs(urlparse(location).query)

        if "error" in parsed:
            error = parsed.get("error", ["unknown"])[0]
            desc = parsed.get("error_description", [""])[0]
            raise AuthenticationError(f"Authentication error: {error}. {desc}")

        if "code" not in parsed:
            raise AuthenticationError("Authorization code not found in redirect")

        return parsed["code"][0]

    @handle_http_errors("Failed to exchange code for token")
    def _exchange_code_for_token(self, auth_code: str) -> str:
        token_endpoint = f"{self.config.iam_url}/realms/{self.config.iam_realm}/protocol/openid-connect/token"

        response = self.session.post(
            token_endpoint,
            data={
                "client_id": self.config.iam_client,
                "redirect_uri": self.config.iam_redirect_uri,
                "code": auth_code,
                "grant_type": "authorization_code",
                "scope": "",
            },
            timeout=10,
        )

        if response.status_code != 200:
            try:
                error_data: Dict[str, Any] = response.json()
                error_msg = error_data.get("error_description", error_data.get("error", "Unknown"))
            except Exception:
                error_msg = response.text[:100]
            raise AuthenticationError(f"Token exchange failed: {error_msg}")

        data: Dict[str, Any] = response.json()
        access_token = data.get("access_token")

        if not access_token:
            raise AuthenticationError("No access token in response")

        return access_token

    def _write_netrc(self, token: str, netrc_path: Optional[Path] = None) -> None:
        """
        Write or update credentials in .netrc file.

        Creates the file if it doesn't exist. Updates existing entry for the
        same host, or appends a new entry if not found.

        Args:
            token: The access token to store as password.
            netrc_path: Path to .netrc file. Defaults to ~/.netrc.

        Raises:
            AuthenticationError: If netrc_host is not configured.
        """
        if not self.netrc_host:
            raise AuthenticationError("Cannot write to .netrc: no host configured")

        netrc_path = netrc_path or Path.home() / ".netrc"

        # Read existing content
        existing_lines: list[str] = []
        if netrc_path.exists():
            existing_lines = netrc_path.read_text().splitlines()

        # Check if entry for this machine already exists
        updated = False
        output_lines: list[str] = []
        i = 0
        while i < len(existing_lines):
            line = existing_lines[i]
            if line.strip().startswith(f"machine {self.netrc_host}"):
                # Skip this machine's existing entry (machine + login + password lines)
                output_lines.append(f"machine {self.netrc_host}")
                output_lines.append("    login anonymous")
                output_lines.append(f"    password {token}")
                updated = True
                i += 1
                # Skip following indented lines (login, password) for this machine
                while i < len(existing_lines) and (
                    existing_lines[i].startswith("    ")
                    or existing_lines[i].startswith("\t")
                    or existing_lines[i].strip().startswith("login")
                    or existing_lines[i].strip().startswith("password")
                ):
                    i += 1
            else:
                output_lines.append(line)
                i += 1

        if not updated:
            # Append new entry
            if output_lines and output_lines[-1].strip():
                output_lines.append("")  # Add blank line before new entry
            output_lines.append(f"machine {self.netrc_host}")
            output_lines.append("    login anonymous")
            output_lines.append(f"    password {token}")

        # Write file with secure permissions
        netrc_path.write_text("\n".join(output_lines) + "\n")
        netrc_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600 permissions

        logger.info(f"Updated .netrc entry for {self.netrc_host}")

    def _get_token_direct(self, user: str, password: str) -> str:
        """
        Get access token using Resource Owner Password Credentials grant.

        This is a simplified alternative to the authorization code flow.
        Uses the keycloak-python library to handle token exchange.

        Args:
            user: Username for authentication.
            password: Password for authentication.

        Returns:
            The access token string.

        Raises:
            AuthenticationError: If token exchange fails.
        """
        try:
            token_data = self.keycloak_client.token(
                username=user,
                password=password,
                grant_type="password",
                scope=self.scope,
            )
            logger.debug(f"Token obtained: {json.dumps(token_data, indent=2)}")
            return token_data.get("access_token")
        except KeycloakError as e:
            logger.error(f"Failed to obtain token: {e}")
            raise AuthenticationError(f"Authentication failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {e}")
            raise AuthenticationError(f"Unexpected authentication error: {e}")

    def _verify_and_decode(self, token: str) -> None:
        """
        Verify the token signature and decode the payload.

        Uses the Keycloak client to decode and verify the token.
        Falls back to unverified decode if verification fails.

        Args:
            token: The JWT access token to verify.
        """
        logger.info("Verifying token...")

        try:
            # Decode and verify the token using keycloak-python
            decoded = self.keycloak_client.decode_token(
                token,
                # verify_signature=True,
                # verify_aud=False,
            )

            logger.info("Token verified successfully")
            logger.debug(json.dumps(decoded, indent=2))
            self.decoded_token = decoded

        except KeycloakError as e:
            logger.warning(f"Token verification failed: {e}")
            logger.debug("Falling back to unverified decode")
            try:
                # Fall back to unverified decode if verification fails
                decoded = self.keycloak_client.decode_token(
                    token,
                )
                logger.debug(json.dumps(decoded, indent=2))
                self.decoded_token = decoded
            except KeycloakError as fallback_error:
                logger.error(f"Failed to decode token even without verification: {fallback_error}")
                raise AuthenticationError(f"Token decode failed: {fallback_error}")
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise AuthenticationError(f"Token verification error: {e}")

    def login(self, write_netrc: bool = False) -> TokenResult:
        """
        Execute the full authentication flow.

        Performs:
        1. Credential collection (interactive or from config)
        2. Token exchange using Resource Owner Password Credentials
        3. Post-auth token processing (if post_auth_hook configured)
        4. Token verification
        5. Token output in configured format
        6. Optionally write to .netrc file

        Args:
            write_netrc: If True, write/update the token in ~/.netrc file.

        Returns:
            TokenResult containing the access token and decoded payload.

        Raises:
            AuthenticationError: If any step of the authentication fails.
        """
        user, password = self._get_credentials()

        logger.info(f"Authenticating on {self.config.iam_url} with user {user}")

        # Prefer authorization-code flow (form submit) for clients that disallow direct grants.
        token: Optional[str] = None
        try:
            # Discover endpoints (keeps compatibility with multiple issuers)
            self._discover_endpoints()

            # Get login form action, submit credentials and extract auth code
            auth_action_url = self._get_auth_url_action()
            login_response = self._perform_login(auth_action_url, user, password)
            auth_code = self._extract_auth_code(login_response)
            token = self._exchange_code_for_token(auth_code)
        except AuthenticationError as e:
            # If auth-code flow fails (e.g. no form available), fall back to direct grant
            logger.info(f"Authorization-code flow failed: {e}. Falling back to direct grant.")
            token = self._get_token_direct(user, password)

        if self.post_auth_hook:
            token = self.post_auth_hook(token, self.config)

        self._verify_and_decode(token)

        if write_netrc:
            self._write_netrc(token)

        return TokenResult(access_token=token, decoded=self.decoded_token)
