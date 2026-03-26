"""HTTP transport layer for ATP client."""

from dataclasses import dataclass, field

import httpx

from atp.core.message import ATPMessage
from atp.discovery.dns import ServerInfo


@dataclass
class TransportResult:
    success: bool
    status_code: int
    body: dict = field(default_factory=dict)
    error: str | None = None


class HTTPTransport:
    def __init__(self, tls_verify: bool = True, timeout: float = 30.0):
        self._verify = tls_verify
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(verify=self._verify, timeout=self._timeout)
        return self._client

    async def post_message(self, server_info: ServerInfo, message: ATPMessage) -> TransportResult:
        """POST to https://{host}:{port}/.well-known/atp/v1/message

        Content-Type: application/atp+json
        Body: message.to_json()
        """
        url = f"https://{server_info.host}:{server_info.port}/.well-known/atp/v1/message"
        try:
            client = self._get_client()
            resp = await client.post(
                url,
                content=message.to_json(),
                headers={"Content-Type": "application/atp+json"},
            )
            body = (
                resp.json()
                if resp.headers.get("content-type", "").startswith("application/json")
                else {}
            )
            return TransportResult(
                success=(resp.status_code == 202),
                status_code=resp.status_code,
                body=body,
            )
        except Exception as e:
            return TransportResult(success=False, status_code=0, error=str(e))

    async def get_capabilities(self, server_info: ServerInfo) -> dict:
        """GET capabilities from the ATP server."""
        url = f"https://{server_info.host}:{server_info.port}/.well-known/atp/v1/capabilities"
        client = self._get_client()
        resp = await client.get(url)
        return resp.json()

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
