"""
Integration tests for destinepyauth library.

Tests interactions between components without mocking external services.
"""

from unittest.mock import patch, MagicMock

from destinepyauth.configs import BaseConfig
from destinepyauth.services import ServiceRegistry, ConfigurationFactory
from destinepyauth.authentication import AuthenticationService, TokenResult


class TestServiceConfigurationIntegration:
    """Integration tests for service configuration."""

    def test_all_services_have_required_config(self):
        """Test that all registered services have required configuration."""
        services = ServiceRegistry.list_services()

        for service_name in services:
            info = ServiceRegistry.get_service_info(service_name)

            # Check required fields
            assert "scope" in info, f"{service_name} missing scope"
            assert "defaults" in info, f"{service_name} missing defaults"

            defaults = info["defaults"]
            assert "iam_client" in defaults, f"{service_name} missing iam_client"
            assert "iam_redirect_uri" in defaults, f"{service_name} missing iam_redirect_uri"

    def test_configuration_factory_with_all_services(self):
        """Test that ConfigurationFactory works with all registered services."""
        services = ServiceRegistry.list_services()

        for service_name in services:
            with patch("destinepyauth.services.Conflator") as mock_conflator:
                mock_config = BaseConfig()
                mock_conflator_instance = MagicMock()
                mock_conflator_instance.load.return_value = mock_config
                mock_conflator.return_value = mock_conflator_instance

                config, scope, hook = ConfigurationFactory.load_config(service_name)

                # Should have applied defaults
                assert config.iam_client is not None
                assert scope is not None

    def test_service_defaults_override_missing_config(self):
        """Test that service defaults are applied when config values are None."""
        with patch("destinepyauth.services.Conflator") as mock_conflator:
            # Create config with no service-specific defaults
            mock_config = BaseConfig(iam_client=None, iam_redirect_uri=None)
            mock_conflator_instance = MagicMock()
            mock_conflator_instance.load.return_value = mock_config
            mock_conflator.return_value = mock_conflator_instance

            # Load config for each service
            services = ["highway", "cacheb", "eden", "streamer", "insula", "dea"]
            for service in services:
                config, _, _ = ConfigurationFactory.load_config(service)

                # Should have applied defaults
                assert config.iam_client is not None
                assert config.iam_redirect_uri is not None
                assert config.iam_url == "https://auth.destine.eu"
                assert config.iam_realm == "desp"


class TestAuthenticationServiceIntegration:
    """Integration tests for authentication service."""

    def test_authentication_service_initialization_with_valid_config(self):
        """Test initializing AuthenticationService with valid configuration."""
        config = BaseConfig(
            iam_client="test-client",
            iam_redirect_uri="https://example.com/callback",
            iam_url="https://auth.example.com",
            iam_realm="test-realm",
        )

        with patch("destinepyauth.authentication.KeycloakOpenID", create=True):
            auth_service = AuthenticationService(
                config=config,
                scope="openid profile",
            )

            assert auth_service.config == config
            assert auth_service.scope == "openid profile"
            assert auth_service.netrc_host == "example.com"

    def test_authentication_service_post_auth_hook(self):
        """Test that post_auth_hook is properly stored."""
        config = BaseConfig(iam_client="test-client")

        def mock_hook(token: str, config: BaseConfig) -> str:
            return f"modified_{token}"

        with patch("destinepyauth.authentication.KeycloakOpenID", create=True):
            auth_service = AuthenticationService(
                config=config,
                scope="openid",
                post_auth_hook=mock_hook,
            )

            assert auth_service.post_auth_hook == mock_hook

    def test_authentication_service_token_result_creation(self):
        """Test creating TokenResult with various configurations."""
        # Test with just access token
        result1 = TokenResult(access_token="access_token_123")
        assert str(result1) == "access_token_123"

        # Test with refresh token
        result2 = TokenResult(
            access_token="access_token_456",
            refresh_token="refresh_token_789",
        )
        assert result2.access_token == "access_token_456"
        assert result2.refresh_token == "refresh_token_789"

        # Test with decoded payload
        decoded = {"sub": "user@example.com", "iss": "https://auth.example.com"}
        result3 = TokenResult(
            access_token="access_token_999",
            decoded=decoded,
        )
        assert result3.decoded == decoded


class TestConfigurationChain:
    """Integration tests for configuration loading chain."""

    def test_configuration_loading_chain_highway(self):
        """Test the complete configuration loading chain for highway."""
        with patch("destinepyauth.services.Conflator") as mock_conflator:
            # Simulate user not providing any specific config
            mock_config = BaseConfig()
            mock_conflator_instance = MagicMock()
            mock_conflator_instance.load.return_value = mock_config
            mock_conflator.return_value = mock_conflator_instance

            config, scope, hook = ConfigurationFactory.load_config("highway")

            # Verify service-specific values
            assert config.iam_client == "highway-public"
            assert "sso/auth/realms/highway" in config.iam_redirect_uri
            assert scope == "openid"
            assert hook is not None

    def test_configuration_loading_chain_cacheb(self):
        """Test the complete configuration loading chain for cacheb."""
        with patch("destinepyauth.services.Conflator") as mock_conflator:
            mock_config = BaseConfig()
            mock_conflator_instance = MagicMock()
            mock_conflator_instance.load.return_value = mock_config
            mock_conflator.return_value = mock_conflator_instance

            config, scope, hook = ConfigurationFactory.load_config("cacheb")

            # Verify service-specific values
            assert config.iam_client == "edh-public"
            assert "cacheb.dcms.destine.eu" in config.iam_redirect_uri
            assert scope == "openid offline_access"
            assert hook is None
