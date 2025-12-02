import logging
import requests
from destinepyauth.configs import BaseConfig
from destinepyauth.exceptions import handle_http_errors, AuthenticationError

logger = logging.getLogger(__name__)


@handle_http_errors("Highway token exchange failed")
def highway_token_exchange(access_token: str, config: BaseConfig) -> str:
    """Exchanges the DESP access token for a HIGHWAY access token."""
    highway_token_url = "https://highway.esa.int/sso/auth/realms/highway/protocol/openid-connect/token"

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": access_token,
        "subject_issuer": "DESP_IAM_PROD",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_id": config.iam_client,
        "audience": "highway-public",
    }

    logger.info("Exchanging DESP token for HIGHWAY token...")
    logger.debug(f"Client ID: {config.iam_client}")

    response = requests.post(highway_token_url, data=data, timeout=10)

    if response.status_code != 200:
        try:
            error_data = response.json()
            error_msg = error_data.get("error_description", error_data.get("error", "Unknown"))
        except Exception:
            error_msg = response.text[:100]
        raise AuthenticationError(f"Exchange failed: {error_msg}")

    result = response.json()
    highway_token = result.get("access_token")

    if not highway_token:
        raise AuthenticationError("No access token in response")

    logger.info("Token exchange successful")
    return highway_token
