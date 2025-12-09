"""
Unit tests for public API functions.

Tests the high-level API including list_services and get_token wrappers.
"""

from destinepyauth.api import list_services


class TestListServicesAPI:
    """Tests for the public list_services API."""

    def test_list_services_returns_list(self):
        """Test that list_services returns a list."""
        services = list_services()
        assert isinstance(services, list)
        assert len(services) > 0

    def test_list_services_contains_known_services(self):
        """Test that list_services contains known services."""
        services = list_services()
        assert "highway" in services
        assert "cacheb" in services
        assert "streamer" in services
        assert "insula" in services
        assert "eden" in services
        assert "dea" in services

    def test_list_services_all_strings(self):
        """Test that all items in list_services are strings."""
        services = list_services()
        assert all(isinstance(s, str) for s in services)
