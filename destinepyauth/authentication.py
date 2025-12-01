import sys
import getpass
import json
from urllib.parse import parse_qs, urlparse
from typing import Tuple, Optional, Callable

import requests
import jwt
from jwt.algorithms import RSAAlgorithm
from lxml import html
from destinepyauth.configs import BaseConfig


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

    def __init__(self, config: BaseConfig, scope: str, post_auth_hook: Optional[Callable] = None):
        self.config = config
        self.scope = scope
        self.post_auth_hook = post_auth_hook
        self.session = requests.Session()
        self.jwks_uri = None  # Will be discovered

    def _discover_endpoints(self):
        """Discover OIDC endpoints to get JWKS URI."""
        try:
            discovery_url = (
                f"{self.config.iam_url}/realms/{self.config.iam_realm}/.well-known/openid-configuration"
            )
            resp = self.session.get(discovery_url)
            if resp.status_code == 200:
                data = resp.json()
                self.jwks_uri = data.get("jwks_uri")
        except Exception as e:
            print(f"Warning: Failed to discover OIDC endpoints: {e}", file=sys.stderr)

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
        # Return refresh_token if present (for offline_access), otherwise access_token
        return data.get("refresh_token", data.get("access_token"))

    def _verify_and_decode(self, token: str):
        """Verify signature and decode token."""
        print("\nVerifying token...", file=sys.stderr)
        try:
            # Get the Key ID from the header (without verification first)
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not self.jwks_uri:
                print("Skipping strict verification (JWKS URI not found). Decoded payload:", file=sys.stderr)
                decoded = jwt.decode(token, options={"verify_signature": False})
                print(json.dumps(decoded, indent=2), file=sys.stderr)
                return

            # Fetch JWKS
            jwks = requests.get(self.jwks_uri).json()
            public_key = None
            for key in jwks["keys"]:
                if key["kid"] == kid:
                    public_key = RSAAlgorithm.from_jwk(json.dumps(key))
                    break

            if public_key:
                decoded = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    audience=self.config.iam_client,
                    options={"verify_aud": False},
                )  # verification of audience often tricky with multiple clients
                print("Token verified successfully. Payload:", file=sys.stderr)
                print(json.dumps(decoded, indent=2), file=sys.stderr)
            else:
                print(f"Could not find public key for kid {kid}. Decoded (unverified):", file=sys.stderr)
                decoded = jwt.decode(token, options={"verify_signature": False})
                print(json.dumps(decoded, indent=2), file=sys.stderr)

        except Exception as e:
            print(f"Token verification failed: {e}", file=sys.stderr)

    def login(self):
        """Main execution method for the authentication flow."""
        self._discover_endpoints()

        user, password = self._get_credentials()

        print(f"Authenticating on {self.config.iam_url} with user {user}", file=sys.stderr)

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
            # Note: The exchanged token might be signed by a different issuer/realm,
            # so strict verification might fail if we use the original realm's JWKS.
            # For Highway, the token comes from the Highway realm, not DESP.
            # Re-discovery might be needed for verification of the exchanged token.

        # Step 6: Verify/Decode
        # If we swapped tokens, we might want to skip verification or discover new JWKS
        # For now, we attempt verification using the original context, or just decode if it fails/warns.
        self._verify_and_decode(token)

        # Output
        print(f"\nlogin anonymous \npassword {token}")
