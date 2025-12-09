"""
End-to-end tests for destinepyauth library.

Tests complete workflows and realistic usage scenarios.
"""

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, MagicMock

from destinepyauth.configs import BaseConfig
from destinepyauth.authentication import AuthenticationService, TokenResult
from destinepyauth.services import ConfigurationFactory, ServiceRegistry
from destinepyauth.api import list_services
from destinepyauth.exceptions import AuthenticationError


class TestEndToEndServiceDiscovery:
    """End-to-end tests for service discovery."""

    def test_discover_and_configure_all_services(self):
        """Test discovering and configuring all available services."""
        services = list_services()

        assert len(services) >= 6, "Expected at least 6 services"

        # Verify we can get info for each service
        for service in services:
            info = ServiceRegistry.get_service_info(service)
            assert "scope" in info
            assert "defaults" in info


class TestEndToEndTokenFlow:
    """End-to-end tests for token acquisition workflows."""

    def test_token_result_mimics_api_response(self):
        """Test that TokenResult properly represents a complete API response."""
        # Simulate a real token response
        access_token = "eyJhbGciOiJSUzI1NiIsInR5cC...truncated"
        refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cC...refresh_truncated"
        decoded_payload = {
            "sub": "user@example.com",
            "exp": 1703500000,
            "iss": "https://auth.destine.eu/realms/desp",
            "aud": "highway-public",
            "scope": "openid",
        }

        result = TokenResult(
            access_token=access_token,
            refresh_token=refresh_token,
            decoded=decoded_payload,
        )

        # Verify token is usable as string
        assert str(result) == access_token

        # Verify all fields are accessible
        assert result.access_token == access_token
        assert result.refresh_token == refresh_token
        assert result.decoded["sub"] == "user@example.com"

    def test_multi_service_token_acquisition_workflow(self):
        """Test acquiring tokens for multiple services in sequence."""
        services_to_test = ["highway", "cacheb", "eden"]
        tokens = {}

        for service in services_to_test:
            with patch("destinepyauth.services.Conflator") as mock_conflator:
                # Setup
                mock_config = BaseConfig(user="testuser", password="testpass")
                mock_conflator_instance = MagicMock()
                mock_conflator_instance.load.return_value = mock_config
                mock_conflator.return_value = mock_conflator_instance

                config, scope, hook = ConfigurationFactory.load_config(service)

                # Verify configuration is correct for each service
                assert config.iam_client is not None
                assert scope is not None

                # Store for later verification
                tokens[service] = {
                    "client": config.iam_client,
                    "scope": scope,
                    "has_hook": hook is not None,
                }

        # Verify different services have different configurations
        assert tokens["highway"]["client"] != tokens["cacheb"]["client"]
        assert tokens["highway"]["has_hook"] != tokens["cacheb"]["has_hook"]


class TestEndToEndNetrcWorkflow:
    """End-to-end tests for .netrc management workflow."""

    def test_complete_netrc_management_workflow(self):
        """Test a complete workflow of creating and managing .netrc entries."""
        with TemporaryDirectory() as tmpdir:
            netrc_path = Path(tmpdir) / ".netrc"

            # Step 1: Initialize authentication service
            config = BaseConfig(iam_client="test-client")
            with patch("destinepyauth.authentication.KeycloakOpenID"):
                auth_service = AuthenticationService(
                    config=config,
                    scope="openid",
                    netrc_host="service1.example.com",
                )

                # Step 2: Write first service token
                auth_service._write_netrc("token_service1", netrc_path=netrc_path)

                # Step 3: Verify file was created
                assert netrc_path.exists()
                content = netrc_path.read_text()
                assert "machine service1.example.com" in content
                assert "password token_service1" in content

            # Step 4: Add another service's credentials
            config2 = BaseConfig(iam_client="test-client-2")
            with patch("destinepyauth.authentication.KeycloakOpenID"):
                auth_service2 = AuthenticationService(
                    config=config2,
                    scope="openid",
                    netrc_host="service2.example.com",
                )
                auth_service2._write_netrc("token_service2", netrc_path=netrc_path)

            # Step 5: Verify both services exist in file
            content = netrc_path.read_text()
            assert "machine service1.example.com" in content
            assert "machine service2.example.com" in content
            assert "password token_service1" in content
            assert "password token_service2" in content


class TestEndToEndErrorHandling:
    """End-to-end tests for error handling in realistic scenarios."""

    def test_error_handling_for_invalid_service(self):
        """Test proper error handling when requesting an invalid service."""
        with pytest.raises(ValueError, match="Unknown service"):
            ServiceRegistry.get_service_info("nonexistent_service")

    def test_error_handling_for_netrc_without_host(self):
        """Test error handling when trying to write netrc without a host."""
        config = BaseConfig(iam_client="test-client")
        with patch("destinepyauth.authentication.KeycloakOpenID"):
            auth_service = AuthenticationService(
                config=config,
                scope="openid",
            )

            with pytest.raises(AuthenticationError, match="no host configured"):
                auth_service._write_netrc("test_token")

    def test_token_validation_with_complete_payload(self):
        """Test token validation with a complete, realistic payload."""
        # Simulate a realistic JWT token payload
        realistic_payload = {
            "jti": "abc123def456",
            "exp": 1703500000,
            "nbf": 0,
            "iat": 1703400000,
            "iss": "https://auth.destine.eu/realms/desp",
            "aud": "highway-public",
            "sub": "user@example.com",
            "typ": "Bearer",
            "azp": "highway-public",
            "session_state": "session123",
            "acr": "1",
            "allowed-origins": ["https://highway.esa.int"],
            "realm_access": {"roles": ["user", "offline_access", "uma_authorization"]},
            "scope": "openid profile email",
        }

        result = TokenResult(
            access_token="test_jwt_token",
            decoded=realistic_payload,
        )

        # Verify payload is properly stored
        assert result.decoded["sub"] == "user@example.com"
        assert result.decoded["iss"] == "https://auth.destine.eu/realms/desp"
        assert "user" in result.decoded["realm_access"]["roles"]


class TestEndToEndServiceConfigurationWorkflow:
    """End-to-end tests for service-specific configuration workflows."""

    def test_highway_service_with_token_exchange_hook(self):
        """Test highway service configuration including token exchange hook."""
        info = ServiceRegistry.get_service_info("highway")

        # Verify highway has specific configuration
        assert info["defaults"]["iam_client"] == "highway-public"
        assert "post_auth_hook" in info
        assert info["post_auth_hook"] is not None

        # Verify the hook is callable
        hook = info["post_auth_hook"]
        assert callable(hook)

    def test_offline_access_services(self):
        """Test services configured for offline access (refresh tokens)."""
        info = ServiceRegistry.get_service_info("cacheb")

        # CacheB should support offline_access for refresh tokens
        assert "offline_access" in info["scope"]

    def test_service_redirect_uri_consistency(self):
        """Test that redirect URIs are consistent and valid."""
        services = ServiceRegistry.list_services()

        for service in services:
            info = ServiceRegistry.get_service_info(service)
            redirect_uri = info["defaults"]["iam_redirect_uri"]

            # All redirect URIs should be https
            assert redirect_uri.startswith("https://"), f"{service} has non-HTTPS redirect URI"

            # All redirect URIs should contain a hostname
            from urllib.parse import urlparse

            parsed = urlparse(redirect_uri)
            assert parsed.netloc, f"{service} redirect URI has no hostname"
