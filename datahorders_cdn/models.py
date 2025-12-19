"""Pydantic models for the DataHorders CDN SDK."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ============================================================================
# Enums
# ============================================================================


class CertificateStatus(str, Enum):
    """Certificate status values."""

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"
    EXPIRED = "expired"
    ERROR = "error"


class CertificateProvider(str, Enum):
    """Certificate provider types."""

    MANUAL = "manual"
    ACME = "acme"


class AcmeProvider(str, Enum):
    """ACME certificate providers."""

    LETSENCRYPT = "letsencrypt"
    ZEROSSL = "zerossl"
    GOOGLE = "google"


class LoadBalanceMethod(str, Enum):
    """Load balancing methods for upstream servers."""

    ROUND_ROBIN = "round_robin"
    LEAST_CONN = "least_conn"
    IP_HASH = "ip_hash"


class ServerProtocol(str, Enum):
    """Protocol for upstream servers."""

    HTTP = "http"
    HTTPS = "https"


class WafMode(str, Enum):
    """WAF operation modes."""

    LOG_ONLY = "log_only"
    BLOCKING = "blocking"


class WafRuleType(str, Enum):
    """WAF rule types."""

    PATTERN = "pattern"
    IP_ALLOW = "ip_allow"
    IP_BLOCK = "ip_block"
    COUNTRY = "country"
    ASN = "asn"
    SQLI = "sqli"
    XSS = "xss"
    RATE_LIMIT = "rate_limit"


class WafMatchTarget(str, Enum):
    """WAF rule match targets."""

    URI = "uri"
    QUERY = "query"
    HEADERS = "headers"
    BODY = "body"
    COOKIES = "cookies"
    USER_AGENT = "user_agent"
    IP = "ip"
    COUNTRY = "country"
    ASN = "asn"
    METHOD = "method"


class WafAction(str, Enum):
    """WAF rule actions."""

    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"
    TARPIT = "tarpit"


class WafSeverity(str, Enum):
    """WAF rule severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IpListType(str, Enum):
    """IP list types (allow/block)."""

    ALLOW = "allow"
    BLOCK = "block"


class HealthCheckProtocol(str, Enum):
    """Health check protocols."""

    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"


class HealthCheckMethod(str, Enum):
    """Health check HTTP methods."""

    HEAD = "HEAD"
    GET = "GET"
    POST = "POST"


# ============================================================================
# Base Models
# ============================================================================


class PaginationMeta(BaseModel):
    """Pagination metadata."""

    page: int
    per_page: int = Field(alias="perPage")
    total: int
    total_pages: int = Field(alias="totalPages")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class ApiResponse(BaseModel):
    """Generic API response wrapper."""

    success: bool
    data: Any = None
    error: Any = None
    meta: PaginationMeta | None = None


# ============================================================================
# Domain Models
# ============================================================================


class ZoneReference(BaseModel):
    """Reference to a zone in domain responses."""

    id: str
    name: str


class DomainZone(BaseModel):
    """Zone association for a domain."""

    zone: ZoneReference


class Domain(BaseModel):
    """Domain model."""

    id: str
    domain: str
    verified: bool
    health_check_enabled: bool = Field(alias="healthCheckEnabled")
    user_id: str = Field(alias="userId")
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")
    zones: list[DomainZone] = Field(default_factory=list)

    class Config:
        """Pydantic config."""

        populate_by_name = True


class DomainVerification(BaseModel):
    """Domain verification information."""

    code: str
    instructions: str


class DomainCreateResponse(BaseModel):
    """Response from creating a domain."""

    domain: Domain
    verification: DomainVerification


class DomainVerifyResponse(BaseModel):
    """Response from verifying a domain."""

    verified: bool
    message: str


class DomainDeleteResponse(BaseModel):
    """Response from deleting a domain."""

    id: str
    deleted: bool


# ============================================================================
# Certificate Models
# ============================================================================


class CertificateDomain(BaseModel):
    """Domain associated with a certificate."""

    domain: str


class Certificate(BaseModel):
    """Certificate model."""

    id: str
    name: str
    provider: CertificateProvider
    acme_provider: AcmeProvider | None = Field(default=None, alias="acmeProvider")
    status: CertificateStatus
    auto_renew: bool = Field(alias="autoRenew")
    is_wildcard: bool = Field(default=False, alias="isWildcard")
    email: str | None = None
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")
    domains: list[CertificateDomain] = Field(default_factory=list)

    class Config:
        """Pydantic config."""

        populate_by_name = True


class AcmeCertificateStatus(BaseModel):
    """ACME certificate status response."""

    certificate_id: str = Field(alias="certificateId")
    name: str | None = None
    status: CertificateStatus
    progress: int
    message: str
    domains: list[str] = Field(default_factory=list)
    created_at: datetime | None = Field(default=None, alias="createdAt")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class CertificateDeleteResponse(BaseModel):
    """Response from deleting a certificate."""

    domain: str
    deleted: bool


# ============================================================================
# Upstream Server Models
# ============================================================================


class UpstreamServer(BaseModel):
    """Upstream server model."""

    id: str
    name: str | None = None
    address: str
    port: int
    protocol: ServerProtocol = ServerProtocol.HTTP
    weight: int = 1
    backup: bool = False
    health_check_path: str | None = Field(default=None, alias="healthCheckPath")
    health_check_connect_timeout: int | None = Field(
        default=None, alias="healthCheckConnectTimeout"
    )
    health_check_timeout: int | None = Field(default=None, alias="healthCheckTimeout")
    health_check_retries: int | None = Field(default=None, alias="healthCheckRetries")
    region: str | None = None
    country: str | None = None
    upstream_id: str | None = Field(default=None, alias="upstreamId")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class Upstream(BaseModel):
    """Upstream configuration model."""

    id: str
    name: str | None = None
    load_balance_method: LoadBalanceMethod = Field(
        default=LoadBalanceMethod.ROUND_ROBIN, alias="loadBalanceMethod"
    )
    servers: list[UpstreamServer] = Field(default_factory=list)

    class Config:
        """Pydantic config."""

        populate_by_name = True


# ============================================================================
# Zone Models
# ============================================================================


class ZoneDomainInfo(BaseModel):
    """Domain info within a zone."""

    id: str
    domain: str
    verified: bool


class ZoneDomain(BaseModel):
    """Domain association in a zone."""

    domain_id: str = Field(alias="domainId")
    is_primary: bool = Field(alias="isPrimary")
    domain: ZoneDomainInfo

    class Config:
        """Pydantic config."""

        populate_by_name = True


class ZoneCertificateDomain(BaseModel):
    """Domain in zone certificate."""

    domain: str


class ZoneCertificate(BaseModel):
    """Certificate info in a zone."""

    id: str
    name: str
    provider: CertificateProvider
    status: CertificateStatus
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    domains: list[ZoneCertificateDomain] = Field(default_factory=list)

    class Config:
        """Pydantic config."""

        populate_by_name = True


class HealthStatus(BaseModel):
    """Health status summary."""

    healthy: int
    unhealthy: int
    disabled: int
    total: int


class Zone(BaseModel):
    """Zone model."""

    id: str
    name: str
    upgrade_insecure: bool = Field(alias="upgradeInsecure")
    four_k_fallback: bool = Field(alias="fourKFallback")
    health_check_enabled: bool = Field(alias="healthCheckEnabled")
    user_id: str = Field(alias="userId")
    certificate_id: str | None = Field(default=None, alias="certificateId")
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")
    deleted_at: datetime | None = Field(default=None, alias="deletedAt")
    domains: list[ZoneDomain] = Field(default_factory=list)
    upstream: Upstream | None = None
    certificate: ZoneCertificate | None = None
    health_status: HealthStatus | None = Field(default=None, alias="healthStatus")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class ZoneDeleteResponse(BaseModel):
    """Response from deleting a zone."""

    id: str
    deleted: bool
    message: str | None = None


# ============================================================================
# Health Check Models
# ============================================================================


class HealthCheckProfile(BaseModel):
    """Health check profile model."""

    id: str
    name: str
    description: str | None = None
    protocol: HealthCheckProtocol = HealthCheckProtocol.HTTP
    port: int = 80
    path: str = "/"
    method: HealthCheckMethod = HealthCheckMethod.HEAD
    expected_status_codes: str = Field(default="200-399", alias="expectedStatusCodes")
    expected_response_text: str | None = Field(
        default=None, alias="expectedResponseText"
    )
    check_interval: int = Field(default=30, alias="checkInterval")
    timeout: int = 10
    retries: int = 2
    follow_redirects: bool = Field(default=False, alias="followRedirects")
    verify_ssl: bool = Field(default=False, alias="verifySSL")
    custom_headers: dict[str, str] | None = Field(
        default=None, alias="customHeaders"
    )
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    server_count: int | None = Field(default=None, alias="serverCount")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class CdnNode(BaseModel):
    """CDN edge node model."""

    id: str
    domain: str
    ip_address: str = Field(alias="ipAddress")
    type: str
    port: int
    resource_path: str = Field(alias="resourcePath")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class HealthCheckToggleResponse(BaseModel):
    """Response from toggling health checks."""

    success: bool
    message: str
    server_id: str = Field(alias="serverId")
    action: str
    reason: str | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


# ============================================================================
# WAF Models
# ============================================================================


class WafRule(BaseModel):
    """WAF rule model."""

    id: str
    zone_config_id: str | None = Field(default=None, alias="zoneConfigId")
    name: str
    description: str | None = None
    rule_type: WafRuleType = Field(alias="ruleType")
    match_target: WafMatchTarget = Field(alias="matchTarget")
    match_pattern: str = Field(alias="matchPattern")
    action: WafAction
    severity: WafSeverity = WafSeverity.MEDIUM
    enabled: bool = True
    priority: int = 500
    metadata: dict[str, Any] | None = None
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafIpEntry(BaseModel):
    """WAF IP list entry model."""

    id: str
    zone_config_id: str | None = Field(default=None, alias="zoneConfigId")
    list_type: IpListType = Field(alias="listType")
    ip_address: str = Field(alias="ipAddress")
    reason: str | None = None
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    created_by: str | None = Field(default=None, alias="createdBy")
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafCountryRule(BaseModel):
    """WAF country blocking rule model."""

    id: str
    zone_config_id: str | None = Field(default=None, alias="zoneConfigId")
    country_code: str = Field(alias="countryCode")
    action: WafAction
    reason: str | None = None
    enabled: bool = True
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafAsnRule(BaseModel):
    """WAF ASN blocking rule model."""

    id: str
    zone_config_id: str | None = Field(default=None, alias="zoneConfigId")
    asn: int
    asn_name: str | None = Field(default=None, alias="asnName")
    action: WafAction
    reason: str | None = None
    enabled: bool = True
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafStats(BaseModel):
    """WAF statistics."""

    total_rules: int = Field(alias="totalRules")
    active_rules: int = Field(alias="activeRules")
    blocked_ips: int = Field(alias="blockedIps")
    allowed_ips: int = Field(alias="allowedIps")
    country_rules: int = Field(alias="countryRules")
    asn_rules: int = Field(alias="asnRules")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafConfig(BaseModel):
    """WAF configuration model."""

    id: str
    zone_id: str = Field(alias="zoneId")
    enabled: bool = True
    mode: WafMode = WafMode.LOG_ONLY
    custom_block_page: str | None = Field(default=None, alias="customBlockPage")
    inherit_global_rules: bool = Field(default=True, alias="inheritGlobalRules")
    sqli_detection: bool = Field(default=True, alias="sqliDetection")
    xss_detection: bool = Field(default=True, alias="xssDetection")
    created_at: datetime | None = Field(default=None, alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    zone_rules: list[WafRule] = Field(default_factory=list, alias="zoneRules")
    ip_lists: list[WafIpEntry] = Field(default_factory=list, alias="ipLists")
    country_rules: list[WafCountryRule] = Field(
        default_factory=list, alias="countryRules"
    )
    asn_rules: list[WafAsnRule] = Field(default_factory=list, alias="asnRules")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafConfigResponse(BaseModel):
    """WAF configuration API response."""

    config: WafConfig
    stats: WafStats


# ============================================================================
# Analytics Models
# ============================================================================


class ZoneUsage(BaseModel):
    """Per-zone usage statistics."""

    zone: str
    gigabytes_sent: float
    requests: int


class DateRange(BaseModel):
    """Date range for analytics."""

    start: datetime
    end: datetime


class TotalTraffic(BaseModel):
    """Total traffic statistics."""

    gigabytes: float


class UsageMetrics(BaseModel):
    """Usage metrics response."""

    total_traffic: TotalTraffic
    total_zones: int
    zones: list[ZoneUsage]
    date_range: DateRange


# ============================================================================
# Request Models (for creating/updating resources)
# ============================================================================


class DomainCreateRequest(BaseModel):
    """Request to create a domain."""

    domain: str
    health_check_enabled: bool = Field(default=False, alias="healthCheckEnabled")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class DomainVerifyRequest(BaseModel):
    """Request to verify a domain."""

    domain: str | None = None
    id: str | None = None


class UpstreamServerCreate(BaseModel):
    """Server configuration for creating upstream."""

    name: str | None = None
    address: str
    port: int = 80
    protocol: ServerProtocol = ServerProtocol.HTTP
    weight: int = 1
    backup: bool = False
    health_check_path: str | None = Field(default=None, alias="healthCheckPath")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class UpstreamCreate(BaseModel):
    """Upstream configuration for zone creation."""

    load_balance_method: LoadBalanceMethod = Field(
        default=LoadBalanceMethod.ROUND_ROBIN, alias="loadBalanceMethod"
    )
    servers: list[UpstreamServerCreate]

    class Config:
        """Pydantic config."""

        populate_by_name = True


class ZoneCreateRequest(BaseModel):
    """Request to create a zone."""

    name: str
    domains: list[str]
    certificate_id: str | None = Field(default=None, alias="certificateId")
    upgrade_insecure: bool = Field(default=True, alias="upgradeInsecure")
    four_k_fallback: bool = Field(default=False, alias="fourKFallback")
    health_check_enabled: bool = Field(default=False, alias="healthCheckEnabled")
    upstream: UpstreamCreate

    class Config:
        """Pydantic config."""

        populate_by_name = True


class ZoneUpdateRequest(BaseModel):
    """Request to update a zone."""

    name: str | None = None
    domains: list[str] | None = None
    certificate_id: str | None = Field(default=None, alias="certificateId")
    force_certificate_removal: bool = Field(
        default=False, alias="forceCertificateRemoval"
    )
    upgrade_insecure: bool | None = Field(default=None, alias="upgradeInsecure")
    four_k_fallback: bool | None = Field(default=None, alias="fourKFallback")
    health_check_enabled: bool | None = Field(default=None, alias="healthCheckEnabled")
    upstream: UpstreamCreate | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


class CertificateCreateRequest(BaseModel):
    """Request to create a manual certificate."""

    name: str
    provider: CertificateProvider = CertificateProvider.MANUAL
    domains: list[str] | None = None
    cert_content: str = Field(alias="certContent")
    key_content: str = Field(alias="keyContent")
    auto_renew: bool = Field(default=False, alias="autoRenew")
    force: bool = False

    class Config:
        """Pydantic config."""

        populate_by_name = True


class AcmeCertificateCreateRequest(BaseModel):
    """Request to create an ACME certificate."""

    name: str
    domains: list[str]
    email: str
    acme_provider: AcmeProvider = Field(
        default=AcmeProvider.LETSENCRYPT, alias="acmeProvider"
    )
    auto_renew: bool = Field(default=True, alias="autoRenew")
    force: bool = False

    class Config:
        """Pydantic config."""

        populate_by_name = True


class CertificateUpdateRequest(BaseModel):
    """Request to update a certificate."""

    name: str | None = None
    auto_renew: bool | None = Field(default=None, alias="autoRenew")
    cert_content: str | None = Field(default=None, alias="certContent")
    key_content: str | None = Field(default=None, alias="keyContent")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class HealthCheckProfileCreateRequest(BaseModel):
    """Request to create a health check profile."""

    name: str
    description: str | None = None
    protocol: HealthCheckProtocol = HealthCheckProtocol.HTTP
    port: int = 80
    path: str = "/"
    method: HealthCheckMethod = HealthCheckMethod.HEAD
    expected_status_codes: str = Field(default="200-399", alias="expectedStatusCodes")
    expected_response_text: str | None = Field(
        default=None, alias="expectedResponseText"
    )
    check_interval: int = Field(default=30, alias="checkInterval")
    timeout: int = 10
    retries: int = 2
    follow_redirects: bool = Field(default=False, alias="followRedirects")
    verify_ssl: bool = Field(default=False, alias="verifySSL")
    custom_headers: dict[str, str] | None = Field(
        default=None, alias="customHeaders"
    )

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafConfigUpdateRequest(BaseModel):
    """Request to update WAF configuration."""

    enabled: bool | None = None
    mode: WafMode | None = None
    custom_block_page: str | None = Field(default=None, alias="customBlockPage")
    inherit_global_rules: bool | None = Field(
        default=None, alias="inheritGlobalRules"
    )
    sqli_detection: bool | None = Field(default=None, alias="sqliDetection")
    xss_detection: bool | None = Field(default=None, alias="xssDetection")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafRuleCreateRequest(BaseModel):
    """Request to create a WAF rule."""

    name: str
    description: str | None = None
    rule_type: WafRuleType = Field(alias="ruleType")
    match_target: WafMatchTarget = Field(alias="matchTarget")
    match_pattern: str = Field(alias="matchPattern")
    action: WafAction
    severity: WafSeverity = WafSeverity.MEDIUM
    enabled: bool = True
    priority: int = 500
    metadata: dict[str, Any] | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafRuleUpdateRequest(BaseModel):
    """Request to update a WAF rule."""

    name: str | None = None
    description: str | None = None
    match_pattern: str | None = Field(default=None, alias="matchPattern")
    action: WafAction | None = None
    severity: WafSeverity | None = None
    enabled: bool | None = None
    priority: int | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafIpCreateRequest(BaseModel):
    """Request to add an IP to the WAF list."""

    list_type: IpListType = Field(alias="listType")
    ip_address: str = Field(alias="ipAddress")
    reason: str | None = None
    expires_at: datetime | None = Field(default=None, alias="expiresAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafIpUpdateRequest(BaseModel):
    """Request to update a WAF IP entry."""

    reason: str | None = None
    expires_at: datetime | None = Field(default=None, alias="expiresAt")

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafCountryCreateRequest(BaseModel):
    """Request to create a country rule."""

    country_code: str = Field(alias="countryCode")
    action: WafAction
    reason: str | None = None
    enabled: bool = True

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafCountryUpdateRequest(BaseModel):
    """Request to update a country rule."""

    action: WafAction | None = None
    reason: str | None = None
    enabled: bool | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafAsnCreateRequest(BaseModel):
    """Request to create an ASN rule."""

    asn: int
    asn_name: str | None = Field(default=None, alias="asnName")
    action: WafAction
    reason: str | None = None
    enabled: bool = True

    class Config:
        """Pydantic config."""

        populate_by_name = True


class WafAsnUpdateRequest(BaseModel):
    """Request to update an ASN rule."""

    asn_name: str | None = Field(default=None, alias="asnName")
    action: WafAction | None = None
    reason: str | None = None
    enabled: bool | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


class UpstreamServerCreateRequest(BaseModel):
    """Request to add an upstream server."""

    name: str
    address: str
    port: int
    protocol: ServerProtocol = ServerProtocol.HTTP
    weight: int = 1
    backup: bool = False
    health_check_path: str = Field(alias="healthCheckPath")
    region: str | None = None
    country: str | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True


class UpstreamServerUpdateRequest(BaseModel):
    """Request to update an upstream server."""

    name: str | None = None
    address: str | None = None
    port: int | None = None
    protocol: ServerProtocol | None = None
    weight: int | None = None
    backup: bool | None = None
    health_check_path: str | None = Field(default=None, alias="healthCheckPath")
    region: str | None = None
    country: str | None = None

    class Config:
        """Pydantic config."""

        populate_by_name = True
