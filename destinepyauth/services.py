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
    Registry to map service names to their specific configuration classes, scopes, and hooks.
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
                # Highway requires a specific redirect URI for the broker flow
                "iam_redirect_uri": "https://highway.esa.int/sso/auth/realms/highway/broker/DESP_IAM_PROD/endpoint"
            },
            "post_auth_hook": highway_token_exchange,
        },
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
    def load_config(service_name: str) -> Tuple[BaseConfig, str, Optional[Callable]]:
        service_info = ServiceRegistry.get_service_info(service_name)
        config_cls: Type[BaseConfig] = service_info["config_cls"]
        scope: str = service_info["scope"]
        hook: Optional[Callable] = service_info.get("post_auth_hook")

        # Load configuration using Conflator
        config: BaseConfig = Conflator("despauth", config_cls).load()

        # Apply overrides if any
        overrides = service_info.get("overrides", {})
        for key, value in overrides.items():
            setattr(config, key, value)

        return config, scope, hook
