"""Shared test fixtures for the DataHorders CDN SDK tests."""

from __future__ import annotations

from collections.abc import Generator

import pytest
import respx

from datahorders_cdn import DataHordersCDN


@pytest.fixture
def api_key() -> str:
    """Return a test API key."""
    return "test-api-key-12345"


@pytest.fixture
def base_url() -> str:
    """Return the base URL for the test API."""
    return "https://dashboard.datahorders.org/api/user/v1"


@pytest.fixture
def client(api_key: str) -> Generator[DataHordersCDN, None, None]:
    """Create a DataHordersCDN client for testing."""
    cdn_client = DataHordersCDN(api_key=api_key)
    yield cdn_client
    cdn_client.close()


@pytest.fixture
def mock_api(base_url: str) -> Generator[respx.MockRouter, None, None]:
    """Create a mock API router for testing HTTP requests."""
    with respx.mock(base_url=base_url, assert_all_called=False) as router:
        yield router


@pytest.fixture
def sample_domain_response() -> dict:
    """Return a sample domain API response."""
    return {
        "data": {
            "id": "dom_test123",
            "domain": "example.com",
            "verified": True,
            "healthCheckEnabled": False,
            "userId": "user_abc123",
            "createdAt": "2024-01-15T10:30:00Z",
            "updatedAt": "2024-01-15T10:30:00Z",
            "zones": [],
        }
    }


@pytest.fixture
def sample_domains_list_response() -> dict:
    """Return a sample domains list API response."""
    return {
        "data": [
            {
                "id": "dom_test123",
                "domain": "example.com",
                "verified": True,
                "healthCheckEnabled": False,
                "userId": "user_abc123",
                "createdAt": "2024-01-15T10:30:00Z",
                "updatedAt": "2024-01-15T10:30:00Z",
                "zones": [],
            },
            {
                "id": "dom_test456",
                "domain": "example.org",
                "verified": False,
                "healthCheckEnabled": True,
                "userId": "user_abc123",
                "createdAt": "2024-01-16T10:30:00Z",
                "updatedAt": "2024-01-16T10:30:00Z",
                "zones": [],
            },
        ],
        "meta": {
            "page": 1,
            "perPage": 10,
            "total": 2,
            "totalPages": 1,
        },
    }


@pytest.fixture
def sample_zone_response() -> dict:
    """Return a sample zone API response."""
    return {
        "data": {
            "id": "zone_test789",
            "name": "app",
            "upgradeInsecure": True,
            "fourKFallback": False,
            "healthCheckEnabled": True,
            "status": "active",
            "upstream": {
                "loadBalanceMethod": "round-robin",
                "servers": [
                    {
                        "id": "srv_001",
                        "name": "Server 1",
                        "address": "10.0.1.100",
                        "port": 8080,
                        "protocol": "http",
                        "weight": 1,
                        "backup": False,
                        "healthCheckPath": "/health",
                    }
                ],
            },
            "createdAt": "2024-01-15T10:30:00Z",
            "updatedAt": "2024-01-15T10:30:00Z",
        }
    }


@pytest.fixture
def sample_certificate_response() -> dict:
    """Return a sample certificate API response."""
    return {
        "data": {
            "id": "cert_test001",
            "name": "example.com SSL",
            "provider": "letsencrypt",
            "status": "active",
            "domains": [
                {"domain": "example.com"},
                {"domain": "*.example.com"},
            ],
            "autoRenew": True,
            "expiresAt": "2024-04-15T10:30:00Z",
            "createdAt": "2024-01-15T10:30:00Z",
            "updatedAt": "2024-01-15T10:30:00Z",
        }
    }
