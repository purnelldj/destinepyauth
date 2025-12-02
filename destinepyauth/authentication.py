"""
Main authentication service for DESP OAuth2 authentication flows.
"""

import getpass
import json
import logging
from urllib.parse import parse_qs, urlparse
from typing import Tuple, Optional, Callable, Dict, Any

import requests
import jwt
from jwt.exceptions import PyJWTError
from lxml import html
from lxml.etree import ParserError

from destinepyauth.configs import BaseConfig
from destinepyauth.exceptions import handle_http_errors, AuthenticationError

logger = logging.getLogger(__name__)


class AuthenticationService:
    """
    Service for handling DESP OAuth2 authentication flows.

    Supports the full OAuth2 authorization code flow including:
    - OIDC endpoint discovery
    - Interactive or configured credential handling
    - Authorization code exchange
    - Token verification and decoding
    - Post-authentication hooks (e.g., token exchange)

    Attributes:
        config: Service configuration containing IAM endpoints and credentials.
        scope: OAuth2 scope string for the authorization request.
        post_auth_hook: Optional callback for post-authentication processing.
        output_format: Output format ('json', 'token', or 'legacy').
    """

    def __init__(
        self,
        config: BaseConfig,
        scope: str,
        post_auth_hook: Optional[Callable[[str, BaseConfig], str]] = None,
        output_format: str = "legacy",
    ) -> None:
        """
        Initialize the authentication service.

        Args:
            config: Configuration containing IAM URL, realm, client, and credentials.
            scope: OAuth2 scope string (e.g., 'openid', 'openid offline_access').
            post_auth_hook: Optional callable for post-auth token processing.
            output_format: Output format - 'json', 'token', or 'legacy'.
        """
        self.config = config
        self.scope = scope
        self.post_auth_hook = post_auth_hook
        self.output_format = output_format
        self.session = requests.Session()
        self.jwks_uri: Optional[str] = None
        self.decoded_token: Optional[Dict[str, Any]] = None

        logger.debug("Configuration loaded:")
        logger.debug(f"  IAM URL: {self.config.iam_url}")
        logger.debug(f"  IAM Realm: {self.config.iam_realm}")
        logger.debug(f"  IAM Client: {self.config.iam_client}")
        logger.debug(f"  Redirect URI: {self.config.iam_redirect_uri}")
        logger.debug(f"  Scope: {self.scope}")

    @handle_http_errors("Failed to discover OIDC endpoints")
    def _discover_endpoints(self) -> None:
        """
        Discover OIDC endpoints from the well-known configuration.

        Fetches the OpenID Connect discovery document and extracts
        the JWKS URI for token verification.

        Raises:
            AuthenticationError: If discovery fails or JWKS URI is missing.
        """
        discovery_url = (
            f"{self.config.iam_url}/realms/{self.config.iam_realm}/.well-known/openid-configuration"
        )
        logger.debug(f"Discovering endpoints from {discovery_url}")

        resp = self.session.get(discovery_url, timeout=10)
        resp.raise_for_status()

        data: Dict[str, Any] = resp.json()
        self.jwks_uri = data.get("jwks_uri")

        if not self.jwks_uri:
            raise AuthenticationError("JWKS URI not found in OpenID configuration")

        logger.debug(f"Discovered JWKS URI: {self.jwks_uri}")

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
        """
        Initiate OAuth2 flow and extract the login form action URL.

        Fetches the Keycloak login page and parses the form action
        URL where credentials should be submitted.

        Returns:
            The form action URL for credential submission.

        Raises:
            AuthenticationError: If the login page cannot be fetched or parsed.
        """
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
        """
        Submit credentials to the login form.

        Args:
            auth_url_action: The form action URL from the login page.
            user: Username for authentication.
            passw: Password for authentication.

        Returns:
            The HTTP response (expected to be a redirect with auth code).
        """
        return self.session.post(
            auth_url_action,
            data={"username": user, "password": passw},
            allow_redirects=False,
            timeout=10,
        )

    def _extract_auth_code(self, login_response: requests.Response) -> str:
        """
        Extract the authorization code from the login redirect.

        Args:
            login_response: The response from credential submission.

        Returns:
            The authorization code string.

        Raises:
            AuthenticationError: If login failed or code not found.
        """
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
        """
        Exchange the authorization code for an access token.

        Args:
            auth_code: The authorization code from the login redirect.

        Returns:
            The access token string.

        Raises:
            AuthenticationError: If token exchange fails.
        """
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

    def _verify_and_decode(self, token: str) -> None:
        """
        Verify the token signature and decode the payload.

        Fetches the JWKS from the issuer, finds the matching key,
        and verifies the token signature. Falls back to unverified
        decode if verification fails.

        Args:
            token: The JWT access token to verify.
        """
        logger.info("Verifying token...")

        try:
            unverified_header: Dict[str, Any] = jwt.get_unverified_header(token)
            unverified_payload: Dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified_payload.get("iss")
            kid = unverified_header.get("kid")

            if not kid:
                raise AuthenticationError("Token missing Key ID (kid)")

            logger.debug(f"Token Issuer: {issuer}")
            logger.debug(f"Token KID: {kid}")

            target_jwks_uri = self.jwks_uri

            # If issuer differs, try to discover keys for that issuer
            if issuer:
                domain_check = urlparse(issuer).netloc
                config_domain = urlparse(self.config.iam_url).netloc

                if domain_check != config_domain or (self.config.iam_realm not in issuer):
                    logger.debug(f"Token issuer differs, fetching keys from {issuer}")
                    try:
                        resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=5)
                        if resp.status_code == 200:
                            target_jwks_uri = resp.json().get("jwks_uri")
                    except Exception as e:
                        logger.warning(f"Failed to discover keys for issuer: {e}")

            logger.debug(f"Using JWKS URI: {target_jwks_uri}")

            if not target_jwks_uri:
                logger.warning("Skipping verification (no JWKS URI)")
                self.decoded_token = unverified_payload
                return

            # Fetch JWKS and build public keys
            jwks_response = requests.get(target_jwks_uri, timeout=5)
            jwks_response.raise_for_status()
            json_certs: list[Dict[str, Any]] = jwks_response.json().get("keys", [])

            public_keys: Dict[str, Any] = {}
            for jwk in json_certs:
                jwk_kid = jwk.get("kid")
                if jwk_kid:
                    try:
                        public_keys[jwk_kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                    except Exception as e:
                        logger.debug(f"Failed to parse key {jwk_kid}: {e}")

            logger.debug(f"Available keys: {list(public_keys.keys())}")

            if kid not in public_keys:
                raise AuthenticationError(
                    f"Token key (kid: {kid}) not found. Available: {list(public_keys.keys())}"
                )

            # Verify and decode
            decoded: Dict[str, Any] = jwt.decode(
                token,
                public_keys[kid],
                algorithms=["RS256"],
                options={"verify_aud": False},
            )

            logger.info("Token verified successfully")
            logger.debug(json.dumps(decoded, indent=2))
            self.decoded_token = decoded

        except PyJWTError as e:
            logger.error(f"Token verification failed: {e}")
            self.decoded_token = unverified_payload
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Verification error: {e}")
            logger.debug("Details:", exc_info=True)
            self.decoded_token = unverified_payload

    def _output_token(self, token: str) -> None:
        """
        Output the token in the configured format.

        Args:
            token: The access token to output.

        Formats:
            - 'json': Full JSON with token and decoded payload
            - 'token': Just the token string (for shell capture)
            - 'legacy': Git credential helper format
        """
        if self.output_format == "json":
            output: Dict[str, Any] = {"access_token": token, "token_type": "Bearer"}
            if self.decoded_token:
                output["decoded"] = self.decoded_token
            print(json.dumps(output, indent=2))
        elif self.output_format == "token":
            print(token)
        elif self.output_format == "legacy":
            print(f"login anonymous \npassword {token}")
        else:
            raise ValueError(f"Unknown output format: {self.output_format}")

    def login(self) -> None:
        """
        Execute the full authentication flow.

        Performs:
        1. OIDC endpoint discovery
        2. Credential collection (interactive or from config)
        3. OAuth2 authorization code flow
        4. Token exchange (if post_auth_hook configured)
        5. Token verification
        6. Token output in configured format

        Raises:
            AuthenticationError: If any step of the authentication fails.
        """
        self._discover_endpoints()
        user, password = self._get_credentials()

        logger.info(f"Authenticating on {self.config.iam_url} with user {user}")

        auth_action_url = self._get_auth_url_action()
        login_response = self._perform_login(auth_action_url, user, password)
        auth_code = self._extract_auth_code(login_response)
        token = self._exchange_code_for_token(auth_code)

        if self.post_auth_hook:
            token = self.post_auth_hook(token, self.config)

        self._verify_and_decode(token)
        self._output_token(token)
