"""Tests for the DataHordersCDN client."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from datahorders_cdn import (
    AuthenticationError,
    DataHordersCDN,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from datahorders_cdn.resources.analytics import AnalyticsResource
from datahorders_cdn.resources.certificates import CertificatesResource
from datahorders_cdn.resources.domains import DomainsResource
from datahorders_cdn.resources.health_checks import HealthChecksResource
from datahorders_cdn.resources.upstream_servers import UpstreamServersResource
from datahorders_cdn.resources.waf import WafResource
from datahorders_cdn.resources.zones import ZonesResource


class TestClientInitialization:
    """Tests for client initialization."""

    def test_client_initializes_with_api_key(self, api_key: str) -> None:
        """Test that the client initializes with an API key."""
        client = DataHordersCDN(api_key=api_key)
        assert client._api_key == api_key
        client.close()

    def test_client_uses_default_base_url(self, api_key: str) -> None:
        """Test that the client uses the default base URL."""
        client = DataHordersCDN(api_key=api_key)
        assert client._base_url == DataHordersCDN.DEFAULT_BASE_URL
        client.close()

    def test_client_accepts_custom_base_url(self, api_key: str) -> None:
        """Test that the client accepts a custom base URL."""
        custom_url = "https://custom.api.example.com/v1"
        client = DataHordersCDN(api_key=api_key, base_url=custom_url)
        assert client._base_url == custom_url
        client.close()

    def test_client_strips_trailing_slash_from_base_url(self, api_key: str) -> None:
        """Test that the client strips trailing slashes from the base URL."""
        client = DataHordersCDN(api_key=api_key, base_url="https://api.example.com/v1/")
        assert client._base_url == "https://api.example.com/v1"
        client.close()

    def test_client_uses_default_timeout(self, api_key: str) -> None:
        """Test that the client uses the default timeout."""
        client = DataHordersCDN(api_key=api_key)
        assert client._timeout == DataHordersCDN.DEFAULT_TIMEOUT
        client.close()

    def test_client_accepts_custom_timeout(self, api_key: str) -> None:
        """Test that the client accepts a custom timeout."""
        client = DataHordersCDN(api_key=api_key, timeout=60)
        assert client._timeout == 60
        client.close()


class TestClientResources:
    """Tests for client resource attributes."""

    def test_client_has_domains_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has a domains resource."""
        assert hasattr(client, "domains")
        assert isinstance(client.domains, DomainsResource)

    def test_client_has_zones_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has a zones resource."""
        assert hasattr(client, "zones")
        assert isinstance(client.zones, ZonesResource)

    def test_client_has_certificates_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has a certificates resource."""
        assert hasattr(client, "certificates")
        assert isinstance(client.certificates, CertificatesResource)

    def test_client_has_health_checks_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has a health_checks resource."""
        assert hasattr(client, "health_checks")
        assert isinstance(client.health_checks, HealthChecksResource)

    def test_client_has_waf_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has a waf resource."""
        assert hasattr(client, "waf")
        assert isinstance(client.waf, WafResource)

    def test_client_has_analytics_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has an analytics resource."""
        assert hasattr(client, "analytics")
        assert isinstance(client.analytics, AnalyticsResource)

    def test_client_has_upstream_servers_resource(self, client: DataHordersCDN) -> None:
        """Test that the client has an upstream_servers resource."""
        assert hasattr(client, "upstream_servers")
        assert isinstance(client.upstream_servers, UpstreamServersResource)


class TestClientHeaders:
    """Tests for client HTTP headers."""

    def test_headers_include_api_key(self, api_key: str) -> None:
        """Test that headers include the API key."""
        client = DataHordersCDN(api_key=api_key)
        headers = client._headers
        assert "X-API-Key" in headers
        assert headers["X-API-Key"] == api_key
        client.close()

    def test_headers_include_content_type(self, client: DataHordersCDN) -> None:
        """Test that headers include content type."""
        headers = client._headers
        assert headers["Content-Type"] == "application/json"

    def test_headers_include_accept(self, client: DataHordersCDN) -> None:
        """Test that headers include accept."""
        headers = client._headers
        assert headers["Accept"] == "application/json"


class TestClientContextManager:
    """Tests for client context manager usage."""

    def test_sync_context_manager(self, api_key: str) -> None:
        """Test that the client works as a sync context manager."""
        with DataHordersCDN(api_key=api_key) as client:
            assert client._api_key == api_key

    @pytest.mark.asyncio
    async def test_async_context_manager(self, api_key: str) -> None:
        """Test that the client works as an async context manager."""
        async with DataHordersCDN(api_key=api_key) as client:
            assert client._api_key == api_key


class TestClientHTTPClients:
    """Tests for lazy HTTP client initialization."""

    def test_sync_client_is_none_initially(self, api_key: str) -> None:
        """Test that the sync client is None initially."""
        client = DataHordersCDN(api_key=api_key)
        assert client._sync_client is None
        client.close()

    def test_async_client_is_none_initially(self, api_key: str) -> None:
        """Test that the async client is None initially."""
        client = DataHordersCDN(api_key=api_key)
        assert client._async_client is None
        client.close()


class TestClientErrorHandling:
    """Tests for client error handling."""

    def test_authentication_error_on_401(
        self, client: DataHordersCDN, mock_api: respx.MockRouter
    ) -> None:
        """Test that 401 responses raise AuthenticationError."""
        mock_api.get("/domains").mock(
            return_value=Response(
                401,
                json={"error": {"message": "Invalid API key", "code": "INVALID_KEY"}},
            )
        )
        with pytest.raises(AuthenticationError) as exc_info:
            client.domains.list()
        assert "Invalid API key" in str(exc_info.value)

    def test_not_found_error_on_404(
        self, client: DataHordersCDN, mock_api: respx.MockRouter
    ) -> None:
        """Test that 404 responses raise NotFoundError."""
        mock_api.get("/domains").mock(
            return_value=Response(
                404,
                json={"error": {"message": "Domain not found", "code": "NOT_FOUND"}},
            )
        )
        with pytest.raises(NotFoundError) as exc_info:
            client.domains.list()
        assert "Domain not found" in str(exc_info.value)

    def test_rate_limit_error_on_429(
        self, client: DataHordersCDN, mock_api: respx.MockRouter
    ) -> None:
        """Test that 429 responses raise RateLimitError."""
        mock_api.get("/domains").mock(
            return_value=Response(
                429,
                json={"error": {"message": "Rate limit exceeded"}},
                headers={"Retry-After": "60"},
            )
        )
        with pytest.raises(RateLimitError) as exc_info:
            client.domains.list()
        assert exc_info.value.retry_after == 60

    def test_validation_error_on_400(
        self, client: DataHordersCDN, mock_api: respx.MockRouter
    ) -> None:
        """Test that 400 responses raise ValidationError."""
        mock_api.post("/domains").mock(
            return_value=Response(
                400,
                json={"error": {"message": "Invalid domain format"}},
            )
        )
        with pytest.raises(ValidationError) as exc_info:
            client.domains.create(domain="invalid")
        assert "Invalid domain format" in str(exc_info.value)


class TestClientRequests:
    """Tests for client HTTP requests."""

    def test_successful_get_request(
        self,
        client: DataHordersCDN,
        mock_api: respx.MockRouter,
        sample_domains_list_response: dict,
    ) -> None:
        """Test a successful GET request."""
        mock_api.get("/domains").mock(
            return_value=Response(200, json=sample_domains_list_response)
        )
        domains, meta = client.domains.list()
        assert len(domains) == 2
        assert domains[0].domain == "example.com"
        assert meta.total == 2

    def test_successful_post_request(
        self,
        client: DataHordersCDN,
        mock_api: respx.MockRouter,
    ) -> None:
        """Test a successful POST request."""
        response_data = {
            "data": {
                "domain": {
                    "id": "dom_new123",
                    "domain": "newdomain.com",
                    "verified": False,
                    "healthCheckEnabled": False,
                    "userId": "user_abc123",
                    "createdAt": "2024-01-15T10:30:00Z",
                    "updatedAt": "2024-01-15T10:30:00Z",
                    "zones": [],
                },
                "verification": {
                    "code": "verify-token-xyz",
                    "instructions": "Add a TXT record with the code",
                },
            }
        }
        mock_api.post("/domains").mock(return_value=Response(200, json=response_data))
        result = client.domains.create(domain="newdomain.com")
        assert result.domain.domain == "newdomain.com"

    @pytest.mark.asyncio
    async def test_successful_async_get_request(
        self,
        client: DataHordersCDN,
        mock_api: respx.MockRouter,
        sample_domains_list_response: dict,
    ) -> None:
        """Test a successful async GET request."""
        mock_api.get("/domains").mock(
            return_value=Response(200, json=sample_domains_list_response)
        )
        domains, meta = await client.domains.list_async()
        assert len(domains) == 2
        assert domains[0].domain == "example.com"
