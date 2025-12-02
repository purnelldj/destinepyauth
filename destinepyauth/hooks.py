import logging
import requests
from destinepyauth.configs import BaseConfig

logger = logging.getLogger(__name__)


def highway_token_exchange(access_token: str, config: BaseConfig) -> str:
    """
    Exchanges the DESP access token for a HIGHWAY access token.
    """
    highway_token_url = "https://highway.esa.int/sso/auth/realms/highway/protocol/openid-connect/token"
    audience = "highway-public"
    # The client_id for the exchange is the same as the initial one
    client_id = config.iam_client

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": access_token,
        "subject_issuer": "DESP_IAM_PROD",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_id": client_id,
        "audience": audience,
    }

    logger.info("Exchanging DESP token for HIGHWAY token...")
    logger.debug(f"Highway token URL: {highway_token_url}")
    logger.debug(f"Client ID: {client_id}")
    logger.debug(f"Audience: {audience}")

    response = requests.post(highway_token_url, data=data)

    if response.status_code != 200:
        logger.error(f"Exchange failed with status {response.status_code}")
        logger.error(f"Response: {response.text}")
        raise Exception(f"Highway token exchange failed: {response.text}")

    logger.info("Token exchange successful")
    return response.json()["access_token"]
