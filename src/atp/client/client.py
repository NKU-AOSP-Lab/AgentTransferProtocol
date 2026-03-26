"""ATP client — build, sign, send, and receive messages."""

import asyncio
from pathlib import Path

from atp.client.transport import HTTPTransport, parse_server_url
from atp.core.message import ATPMessage
from atp.core.signature import Signer
from atp.storage.config import ConfigStorage
from atp.storage.keys import KeyStorage


def _extract_domain(server: str) -> str:
    """Extract the domain/host from a server string (strip scheme and port)."""
    domain = server
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split(":")[0]
    return domain


def _auto_complete_agent_id(agent_id: str, server: str) -> str:
    """If agent_id has no '@', append @domain from server."""
    if "@" not in agent_id:
        domain = _extract_domain(server)
        return f"{agent_id}@{domain}"
    return agent_id


class ATPClient:
    def __init__(
        self,
        agent_id: str,
        server: str,
        config_dir: Path | None = None,
        no_verify: bool = False,
        password: str | None = None,
    ):
        self._server = server
        self._base_url, self._is_https = parse_server_url(server)
        self._agent_id = _auto_complete_agent_id(agent_id, server)
        self._password = password
        self._config_storage = ConfigStorage(config_dir)
        self._config = self._config_storage.load()
        self._no_verify = no_verify
        self._transport = HTTPTransport(no_verify=no_verify)
        self._keys = KeyStorage(self._config_storage.config_dir / "keys")

    async def send(
        self,
        to: str,
        payload: dict | None = None,
        body: str | None = None,
        subject: str | None = None,
    ) -> dict:
        """Build, sign, and send a message."""
        if payload is None:
            payload = {}
            if body:
                payload["body"] = body
            if subject:
                payload["subject"] = subject

        msg = ATPMessage.create(from_id=self._agent_id, to_id=to, payload=payload)

        # Sign
        selector = self._config.key_selector or "default"
        domain = self._agent_id.split("@")[1] if "@" in self._agent_id else "localhost"
        private_key = self._keys.load_private_key(selector)
        signer = Signer(private_key, selector, domain)
        signer.sign(msg)

        # Send
        auth = (self._agent_id, self._password) if self._password else None
        result = await self._transport.post_message(self._base_url, msg, auth=auth)

        if result.success:
            return {"status": "accepted", "nonce": msg.nonce, "timestamp": msg.timestamp}
        else:
            return {
                "status": "error",
                "error": result.error or f"HTTP {result.status_code}",
                "nonce": msg.nonce,
            }

    async def recv(
        self,
        limit: int = 50,
        wait: bool = False,
        timeout: float = 30.0,
    ) -> list[ATPMessage]:
        """Receive messages from server. Requires Credential authentication."""
        url = f"{self._base_url}/.well-known/atp/v1/messages"
        params = {"limit": str(limit)}

        # Build auth headers
        headers = {}
        if self._password:
            import base64 as b64
            cred = b64.b64encode(f"{self._agent_id}:{self._password}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        else:
            params["agent_id"] = self._agent_id

        client = self._transport._get_client()

        if wait:
            loop = asyncio.get_event_loop()
            deadline = loop.time() + timeout
            while loop.time() < deadline:
                resp = await client.get(url, params=params, headers=headers)
                data = resp.json()
                messages = data.get("messages", [])
                if messages:
                    return [ATPMessage.from_dict(m) for m in messages]
                await asyncio.sleep(2)
            return []
        else:
            resp = await client.get(url, params=params, headers=headers)
            data = resp.json()
            messages = data.get("messages", [])
            return [ATPMessage.from_dict(m) for m in messages]

    async def close(self) -> None:
        await self._transport.close()
