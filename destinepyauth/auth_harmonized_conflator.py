#! /usr/bin/env python3

from urllib.parse import parse_qs, urlparse
import sys

import argparse
import requests
from conflator import Conflator
from lxml import html
import getpass

from destinepyauth.configs import (
    BaseConfig,
    CacheBConfig,
    StreamerConfig,
    InsulaConfig,
    EdenConfig,
    DEAConfig,
    HighwayConfig,
)


def main(
    service: str,
):
    """
    service can be: 'cacheb', 'streamer', 'insula', 'eden', 'dea', 'highway'
    """
    if service == "cacheb":
        config: BaseConfig = Conflator("despauth", CacheBConfig).load()
        scope = "openid offline_access"
    elif service == "streamer":
        config: BaseConfig = Conflator("despauth", StreamerConfig).load()
        scope = "openid"
    elif service == "insula":
        config: BaseConfig = Conflator("despauth", InsulaConfig).load()
        scope = "openid"
    elif service == "eden":
        config: BaseConfig = Conflator("despauth", EdenConfig).load()
        scope = "openid"
    elif service == "dea":
        config: BaseConfig = Conflator("despauth", DEAConfig).load()
        scope = "openid"
    elif service == "highway":
        config: BaseConfig = Conflator("despauth", HighwayConfig).load()
        scope = "openid"

    if config.user is None:
        user = input("Username: ")
    else:
        user = config.user

    if config.password is None:
        password = getpass.getpass("Password: ")
    else:
        password = config.password

    print(f"Authenticating on {config.iam_url} with user {user}", file=sys.stderr)

    with requests.Session() as s:
        # Get the auth url
        response = s.get(
            url=config.iam_url + "/realms/" + config.iam_realm + "/protocol/openid-connect/auth",
            params={
                "client_id": config.iam_client,
                "redirect_uri": config.iam_redirect_uri,
                "scope": scope,
                "response_type": "code",
            },
        )
        response.raise_for_status()
        auth_url = html.fromstring(response.content.decode()).forms[0].action

        # Login and get auth code
        login = s.post(
            auth_url,
            data={
                "username": user,
                "password": password,
            },
            allow_redirects=False,
        )

        # We expect a 302, a 200 means we got sent back to the login page and there's probably an error message
        if login.status_code == 200:
            tree = html.fromstring(login.content)
            error_message_element = tree.xpath('//span[@id="input-error"]/text()')
            error_message = (
                error_message_element[0].strip() if error_message_element else "Error message not found"
            )
            raise Exception(error_message)

        if login.status_code != 302:
            raise Exception("Login failed")

        auth_code = parse_qs(urlparse(login.headers["Location"]).query)["code"][0]

        # Use the auth code to get the token
        response = requests.post(
            config.iam_url + "/realms/" + config.iam_realm + "/protocol/openid-connect/token",
            data={
                "client_id": config.iam_client,
                "redirect_uri": config.iam_redirect_uri,
                "code": auth_code,
                "grant_type": "authorization_code",
                "scope": "",
            },
        )

        if response.status_code != 200:
            raise Exception("Failed to get token")

        # instead of storing the access token, we store the offline_access (kind of "refresh") token
        token = response.json()["refresh_token"]

        print(f"\nlogin anonymous \npassword {token}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get token from desp iam.")

    parser.add_argument(
        "--SERVICE",
        "-s",
        required=True,
        type=str,
        help="Service can be one of either 'streamer', or 'cacheb'",
    )

    s = parser.parse_args()

    main(s.SERVICE)
