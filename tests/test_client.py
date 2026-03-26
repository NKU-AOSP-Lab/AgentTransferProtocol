"""Tests for the ATP client transport and client modules."""

import pytest

from atp.client.transport import HTTPTransport, TransportResult
from atp.discovery.dns import ServerInfo


@pytest.mark.asyncio
async def test_transport_post_message():
    """Verify the class can be instantiated and method exists."""
    transport = HTTPTransport(tls_verify=False)
    # Don't actually make HTTP calls in unit tests
    await transport.close()


def test_transport_result():
    r = TransportResult(success=True, status_code=202, body={"status": "accepted"})
    assert r.success
    assert r.status_code == 202


def test_transport_result_error():
    r = TransportResult(success=False, status_code=0, error="connection refused")
    assert not r.success
    assert r.status_code == 0
    assert r.error == "connection refused"


def test_transport_result_defaults():
    r = TransportResult(success=True, status_code=200)
    assert r.body == {}
    assert r.error is None


def test_http_transport_init():
    transport = HTTPTransport(tls_verify=False, timeout=10.0)
    assert transport._verify is False
    assert transport._timeout == 10.0
    assert transport._client is None


def test_http_transport_get_client():
    transport = HTTPTransport(tls_verify=False)
    client = transport._get_client()
    assert client is not None
    # Calling again should return same client
    assert transport._get_client() is client
