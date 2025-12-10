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

import base64
import requests
from lxml import html
from lxml.etree import ParserError

from authlib.jose import JsonWebKey, jwt as authlib_jwt

from destinepyauth.configs import BaseConfig
from destinepyauth.exceptions import AuthenticationError, handle_http_errors

logger = logging.getLogger(__name__)


@dataclass
class TokenResult:
    """Result of an authentication operation."""

    access_token: str
    """The access token string."""

    refresh_token: Optional[str] = None
    """The refresh token string (if available)."""

    decoded: Optional[Dict[str, Any]] = None
    """Decoded token payload (if verification succeeded)."""

    def __str__(self) -> str:
        return self.access_token


class AuthenticationService:
    """
    Service for handling DESP OAuth2 authentication flows.

    Supports the full OAuth2 authorization code flow including:
    - Interactive or configured credential handling
    - Token verification and decoding
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
    def _exchange_code_for_token(self, auth_code: str) -> Dict[str, Any]:
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

        if "access_token" not in data and "refresh_token" not in data:
            raise AuthenticationError("No token in response")

        return data

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

    def _verify_and_decode(self, token: str) -> None:
        """
        Verify the token signature and decode the payload.

        Args:
            token: The JWT access token to verify.
        """
        logger.debug("Verifying token...")

        # ---- 1. Extract header and payload without verifying ----
        try:
            header_b64, payload_b64, _ = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        except Exception as e:
            raise ValueError(f"Invalid token format: {e}")

        issuer = payload.get("iss")
        kid = header.get("kid")

        if not issuer:
            raise ValueError("Token has no issuer (iss)")
        if not kid:
            raise ValueError("Token has no key ID (kid)")

        # ---- 2. Discover issuer JWKS URI ----
        # This automatically handles Keycloak, Auth0, etc.
        oidc_config = requests.get(f"{issuer}/.well-known/openid-configuration").json()
        jwks_uri = oidc_config["jwks_uri"]

        # ---- 3. Fetch JWKS ----
        jwks = JsonWebKey.import_key_set(requests.get(jwks_uri).json())

        # ---- 4. Verify the token signature and claims ----
        try:
            claims = authlib_jwt.decode(
                token,
                key=jwks,
                claims_options={
                    # Disable audience validation if needed
                    "aud": {"essential": False},
                },
            )
            # Standard claims validation (exp, nbf, iat, iss)
            claims.validate()
            claims = dict(claims)
            logger.info("Token verified successfully")
            logger.debug(json.dumps(claims, indent=2))
            self.decoded_token = claims
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
        return

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
        token_data: Optional[Dict[str, Any]] = None

        # Get login form action, submit credentials and extract auth code
        auth_action_url = self._get_auth_url_action()
        login_response = self._perform_login(auth_action_url, user, password)
        auth_code = self._extract_auth_code(login_response)
        token_data = self._exchange_code_for_token(auth_code)

        if not token_data:
            raise AuthenticationError("Failed to obtain token data")

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if self.post_auth_hook and access_token:
            access_token = self.post_auth_hook(access_token, self.config)

        # Verify and decode using access token (if available)
        if access_token:
            self._verify_and_decode(access_token)
        else:
            self.decoded_token = None

        # When writing to .netrc, prefer storing the refresh token (if present),
        # otherwise fall back to the access token to preserve previous behavior.
        if write_netrc:
            token_to_store = refresh_token or access_token
            if not token_to_store:
                raise AuthenticationError("No token available to write to .netrc")
            self._write_netrc(token_to_store)

        return TokenResult(access_token=access_token, refresh_token=refresh_token, decoded=self.decoded_token)
