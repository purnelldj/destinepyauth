#! /usr/bin/env python3

import sys
import argparse
import getpass
from urllib.parse import parse_qs, urlparse
from typing import Dict, Any, Tuple, Type

import requests
from lxml import html
from conflator import Conflator

from destinepyauth.configs import (
    BaseConfig,
    CacheBConfig,
    StreamerConfig,
    InsulaConfig,
    EdenConfig,
    DEAConfig,
    HighwayConfig,
)


class ServiceRegistry:
    """
    Registry to map service names to their specific configuration classes and scopes.
    """

    _REGISTRY: Dict[str, Dict[str, Any]] = {
        "cacheb": {"config_cls": CacheBConfig, "scope": "openid offline_access"},
        "streamer": {"config_cls": StreamerConfig, "scope": "openid"},
        "insula": {"config_cls": InsulaConfig, "scope": "openid"},
        "eden": {"config_cls": EdenConfig, "scope": "openid"},
        "dea": {"config_cls": DEAConfig, "scope": "openid"},
        "highway": {"config_cls": HighwayConfig, "scope": "openid"},
    }

    @classmethod
    def get_service_info(cls, service_name: str) -> Dict[str, Any]:
        if service_name not in cls._REGISTRY:
            raise ValueError(
                f"Unknown service: {service_name}. " f"Available services: {', '.join(cls._REGISTRY.keys())}"
            )
        return cls._REGISTRY[service_name]


class ConfigurationFactory:
    """
    Factory to load the appropriate configuration object using Conflator.
    """

    @staticmethod
    def load_config(service_name: str) -> Tuple[BaseConfig, str]:
        service_info = ServiceRegistry.get_service_info(service_name)
        config_cls: Type[BaseConfig] = service_info["config_cls"]
        scope: str = service_info["scope"]

        # Load configuration using Conflator
        config: BaseConfig = Conflator("despauth", config_cls).load()
        return config, scope


class AuthenticationService:
    """
    Handles the authentication flow:
    1. Fetch login page to get action URL
    2. Post credentials
    3. Extract auth code
    4. Exchange code for token
    """

    def __init__(self, config: BaseConfig, scope: str):
        self.config = config
        self.scope = scope
        self.session = requests.Session()

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

    def login(self):
        """Main execution method for the authentication flow."""
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

        # Output
        print(f"\nlogin anonymous \npassword {token}")


def main():
    parser = argparse.ArgumentParser(description="Get token from desp iam.")

    parser.add_argument(
        "--SERVICE",
        "-s",
        required=True,
        type=str,
        help="Service name (e.g. 'streamer', 'cacheb', 'highway', etc.)",
    )

    args = parser.parse_args()

    try:
        # Load Config
        config, scope = ConfigurationFactory.load_config(args.SERVICE)

        # Initialize Service
        auth_service = AuthenticationService(config, scope)

        # Execute
        auth_service.login()

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
