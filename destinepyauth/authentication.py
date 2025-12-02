import getpass
import json
import logging
from urllib.parse import parse_qs, urlparse
from typing import Tuple, Optional, Callable

import requests
import jwt
from lxml import html
from destinepyauth.configs import BaseConfig

# Configure logger
logger = logging.getLogger(__name__)


class AuthenticationService:
    """
    Handles the authentication flow:
    1. Fetch login page to get action URL
    2. Post credentials
    3. Extract auth code
    4. Exchange code for token
    5. (Optional) Execute post-auth hook
    6. (Optional) Verify/Decode token
    """

    def __init__(
        self,
        config: BaseConfig,
        scope: str,
        post_auth_hook: Optional[Callable] = None,
        output_format: str = "legacy",
    ):
        self.config = config
        self.scope = scope
        self.post_auth_hook = post_auth_hook
        self.output_format = output_format
        self.session = requests.Session()
        self.jwks_uri = None  # Will be discovered
        self.decoded_token = None  # Store decoded token for output

        # Log configuration
        logger.debug("Configuration loaded:")
        logger.debug(f"  IAM URL: {self.config.iam_url}")
        logger.debug(f"  IAM Realm: {self.config.iam_realm}")
        logger.debug(f"  IAM Client: {self.config.iam_client}")
        logger.debug(f"  Redirect URI: {self.config.iam_redirect_uri}")
        logger.debug(f"  Scope: {self.scope}")

    def _discover_endpoints(self):
        """Discover OIDC endpoints to get JWKS URI."""
        try:
            discovery_url = (
                f"{self.config.iam_url}/realms/{self.config.iam_realm}/.well-known/openid-configuration"
            )
            logger.debug(f"Discovering endpoints from {discovery_url}")
            resp = self.session.get(discovery_url)
            if resp.status_code == 200:
                data = resp.json()
                self.jwks_uri = data.get("jwks_uri")
                logger.debug(f"Discovered JWKS URI: {self.jwks_uri}")
            else:
                logger.error(f"Discovery failed with status {resp.status_code}")
        except Exception as e:
            logger.warning(f"Failed to discover OIDC endpoints: {e}")

    def _get_credentials(self) -> Tuple[str, str]:
        """Retrieve username and password from config or prompt user."""
        if self.config.user is None:
            user = input("Username: ")
        else:
            user = self.config.user

        if self.config.password is None:
            password = getpass.getpass("Password: ")
        else:
            password = self.config.password

        return user, password

    def _get_auth_url_action(self) -> str:
        """Initiate the OIDC flow and retrieve the actual login form action URL."""
        auth_endpoint = f"{self.config.iam_url}/realms/{self.config.iam_realm}/protocol/openid-connect/auth"
        params = {
            "client_id": self.config.iam_client,
            "redirect_uri": self.config.iam_redirect_uri,
            "scope": self.scope,
            "response_type": "code",
        }

        response = self.session.get(url=auth_endpoint, params=params)
        response.raise_for_status()

        # Parse the form action from the returned HTML
        tree = html.fromstring(response.content.decode())
        forms = tree.forms
        if not forms:
            raise Exception("No login form found in the response.")
        return forms[0].action

    def _perform_login(self, auth_url_action: str, user: str, passw: str) -> requests.Response:
        """Post credentials to the login form."""
        return self.session.post(
            auth_url_action,
            data={
                "username": user,
                "password": passw,
            },
            allow_redirects=False,
        )

    def _extract_auth_code(self, login_response: requests.Response) -> str:
        """Check login success and extract authorization code from redirect."""
        # Check for login errors (Keycloak often returns 200 OK with error text on failure)
        if login_response.status_code == 200:
            tree = html.fromstring(login_response.content)
            error_message_element = tree.xpath('//span[@id="input-error"]/text()')
            error_message = (
                error_message_element[0].strip()
                if error_message_element
                else "Unknown login error (page 200 OK)"
            )
            raise Exception(f"Login failed: {error_message}")

        if login_response.status_code != 302:
            raise Exception(f"Login failed with status code {login_response.status_code}")

        # Extract code from the Location header
        location = login_response.headers.get("Location", "")
        parsed = parse_qs(urlparse(location).query)
        if "code" not in parsed:
            raise Exception("Authorization code not found in redirect URL")

        return parsed["code"][0]

    def _exchange_code_for_token(self, auth_code: str) -> str:
        """Exchange authorization code for access/refresh token."""
        token_endpoint = f"{self.config.iam_url}/realms/{self.config.iam_realm}/protocol/openid-connect/token"

        response = requests.post(
            token_endpoint,
            data={
                "client_id": self.config.iam_client,
                "redirect_uri": self.config.iam_redirect_uri,
                "code": auth_code,
                "grant_type": "authorization_code",
                "scope": "",
            },
        )

        if response.status_code != 200:
            raise Exception(f"Failed to get token: {response.text}")

        data = response.json()
        # Return access_token (not refresh_token, as refresh tokens have different signing keys)
        return data.get("access_token")

    def _verify_and_decode(self, token: str):
        """Verify signature and decode token using the same approach as auth_eden.py."""
        logger.info("Verifying token...")
        try:
            # 1. Decode unverified first to get issuer/kid
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified_payload.get("iss")
            kid = unverified_header.get("kid")

            logger.debug(f"Token Issuer: {issuer}")
            logger.debug(f"Token KID: {kid}")

            target_jwks_uri = self.jwks_uri

            # 2. If issuer differs from config, try to discover keys for that issuer
            if issuer:
                try:
                    domain_check = urlparse(issuer).netloc
                    config_domain = urlparse(self.config.iam_url).netloc

                    if domain_check != config_domain or (self.config.iam_realm not in issuer):
                        logger.debug(f"Token issuer ({issuer}) differs from config. Fetching new keys...")
                        discovery_url = f"{issuer}/.well-known/openid-configuration"
                        resp = requests.get(discovery_url, timeout=5)
                        if resp.status_code == 200:
                            target_jwks_uri = resp.json().get("jwks_uri")
                            logger.debug(f"New JWKS URI: {target_jwks_uri}")
                except Exception as e:
                    logger.warning(f"Failed to discover keys for issuer {issuer}: {e}")

            logger.debug(f"Using JWKS URI: {target_jwks_uri}")

            if not target_jwks_uri:
                logger.warning("Skipping strict verification (JWKS URI not found)")
                self.decoded_token = unverified_payload
                return

            # 3. Fetch JWKS and build public_keys dict (exactly like auth_eden.py)
            json_certs = requests.get(target_jwks_uri).json().get("keys")
            public_keys = {}
            found_kids = []
            for jwk in json_certs:
                jwk_kid = jwk["kid"]
                found_kids.append(jwk_kid)
                public_keys[jwk_kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

            logger.debug(f"JWKS KIDs found: {found_kids}")

            if kid not in public_keys:
                logger.error(f"Could not find public key for kid {kid}. Available keys: {found_kids}")
                self.decoded_token = unverified_payload
                return

            # 4. Decode and Verify (exactly like auth_eden.py)
            decoded = jwt.decode(
                token,
                public_keys[kid],
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
            logger.info("Token verified successfully")
            logger.debug("Token payload:")
            logger.debug(json.dumps(decoded, indent=2))
            self.decoded_token = decoded

        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            logger.debug("Exception details:", exc_info=True)
            # Fallback decode
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                self.decoded_token = decoded
            except Exception:
                pass

    def _output_token(self, token: str):
        """Output the token in the requested format."""
        if self.output_format == "json":
            # Output full token response as JSON
            output = {"access_token": token, "token_type": "Bearer"}
            if self.decoded_token:
                output["decoded"] = self.decoded_token
            print(json.dumps(output, indent=2))

        elif self.output_format == "token":
            # Output just the token (useful for export TOKEN=$(...)
            print(token)

        elif self.output_format == "legacy":
            # Output in the legacy format (for git credential helpers, etc.)
            print(f"login anonymous \npassword {token}")

        else:
            raise ValueError(f"Unknown output format: {self.output_format}")

    def login(self):
        """Main execution method for the authentication flow."""
        self._discover_endpoints()

        user, password = self._get_credentials()

        logger.info(f"Authenticating on {self.config.iam_url} with user {user}")

        # Step 1: Get form action
        auth_action_url = self._get_auth_url_action()

        # Step 2: Login
        login_response = self._perform_login(auth_action_url, user, password)

        # Step 3: Get Code
        auth_code = self._extract_auth_code(login_response)

        # Step 4: Get Token
        token = self._exchange_code_for_token(auth_code)

        # Step 5: Post-Auth Hook (e.g. Highway Token Exchange)
        if self.post_auth_hook:
            token = self.post_auth_hook(token, self.config)

        # Step 6: Verify/Decode
        self._verify_and_decode(token)

        # Step 7: Output
        self._output_token(token)
