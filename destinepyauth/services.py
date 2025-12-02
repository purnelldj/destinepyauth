"""
Service registry and configuration factory for destinepyauth.
"""

from typing import Dict, Any, Tuple, Type, Callable, Optional

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
from destinepyauth.hooks import highway_token_exchange


class ServiceRegistry:
    """
    Registry mapping service names to their configuration classes, scopes, and hooks.

    Provides a centralized lookup for service-specific settings including:
    - Configuration class for loading credentials and endpoints
    - OAuth scope requirements
    - Post-authentication hooks (e.g., token exchange)
    - Configuration overrides
    """

    _REGISTRY: Dict[str, Dict[str, Any]] = {
        "cacheb": {"config_cls": CacheBConfig, "scope": "openid offline_access"},
        "streamer": {"config_cls": StreamerConfig, "scope": "openid"},
        "insula": {"config_cls": InsulaConfig, "scope": "openid"},
        "eden": {"config_cls": EdenConfig, "scope": "openid"},
        "dea": {"config_cls": DEAConfig, "scope": "openid"},
        "highway": {
            "config_cls": HighwayConfig,
            "scope": "openid",
            "overrides": {
                "iam_redirect_uri": "https://highway.esa.int/sso/auth/realms/highway/broker/DESP_IAM_PROD/endpoint"
            },
            "post_auth_hook": highway_token_exchange,
        },
    }

    @classmethod
    def get_service_info(cls, service_name: str) -> Dict[str, Any]:
        """
        Get configuration info for a service.

        Args:
            service_name: Name of the service (e.g., 'eden', 'highway').

        Returns:
            Dictionary containing config_cls, scope, and optional overrides/hooks.

        Raises:
            ValueError: If the service name is not registered.
        """
        if service_name not in cls._REGISTRY:
            available = ", ".join(cls._REGISTRY.keys())
            raise ValueError(f"Unknown service: {service_name}. Available: {available}")
        return cls._REGISTRY[service_name]

    @classmethod
    def list_services(cls) -> list[str]:
        """
        List all available service names.

        Returns:
            List of registered service names.
        """
        return list(cls._REGISTRY.keys())


class ConfigurationFactory:
    """Factory for loading service configurations using Conflator."""

    @staticmethod
    def load_config(service_name: str) -> Tuple[BaseConfig, str, Optional[Callable[[str, BaseConfig], str]]]:
        """
        Load configuration for a service.

        Uses Conflator to load configuration from environment variables,
        config files, and CLI arguments, then applies any service-specific overrides.

        Args:
            service_name: Name of the service to configure.

        Returns:
            Tuple of (config, scope, post_auth_hook) where:
            - config: Loaded BaseConfig instance
            - scope: OAuth scope string
            - post_auth_hook: Optional callable for post-auth processing
        """
        service_info = ServiceRegistry.get_service_info(service_name)
        config_cls: Type[BaseConfig] = service_info["config_cls"]
        scope: str = service_info["scope"]
        hook: Optional[Callable[[str, BaseConfig], str]] = service_info.get("post_auth_hook")

        # Load configuration using Conflator
        config: BaseConfig = Conflator("despauth", config_cls).load()

        # Apply overrides if any
        overrides: Dict[str, Any] = service_info.get("overrides", {})
        for key, value in overrides.items():
            setattr(config, key, value)

        return config, scope, hook
