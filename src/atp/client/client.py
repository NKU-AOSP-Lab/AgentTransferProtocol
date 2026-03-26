"""ATP client — build, sign, send, and receive messages."""

import asyncio
from pathlib import Path

from atp.client.transport import HTTPTransport
from atp.core.message import ATPMessage
from atp.core.signature import Signer
from atp.discovery.dns import ServerInfo
from atp.storage.config import ConfigStorage
from atp.storage.keys import KeyStorage


class ATPClient:
    def __init__(
        self,
        agent_id: str,
        config_dir: Path | None = None,
        server_url: str | None = None,
        local_mode: bool = False,
        password: str | None = None,
    ):
        self._agent_id = agent_id
        self._password = password
        self._config_storage = ConfigStorage(config_dir)
        self._config = self._config_storage.load()
        self._server_url = server_url
        self._local_mode = local_mode
        self._transport = HTTPTransport(tls_verify=not local_mode)
        self._keys = KeyStorage(self._config_storage.config_dir / "keys")

    def _get_server_info(self) -> ServerInfo:
        """Get server connection info from server_url or config."""
        if self._server_url:
            # Parse "host:port" or "host"
            parts = self._server_url.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 7443
        else:
            host = "localhost"
            port = self._config.server.port or 7443
        return ServerInfo(host=host, port=port)

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
        server_info = self._get_server_info()
        auth = (self._agent_id, self._password) if self._password else None
        result = await self._transport.post_message(server_info, msg, auth=auth)

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
        """Receive messages from local server."""
        server_info = self._get_server_info()
        url = f"https://{server_info.host}:{server_info.port}/.well-known/atp/v1/messages"
        params = {"agent_id": self._agent_id, "limit": str(limit)}

        client = self._transport._get_client()

        if wait:
            loop = asyncio.get_event_loop()
            deadline = loop.time() + timeout
            while loop.time() < deadline:
                resp = await client.get(url, params=params)
                data = resp.json()
                messages = data.get("messages", [])
                if messages:
                    return [ATPMessage.from_dict(m) for m in messages]
                await asyncio.sleep(2)
            return []
        else:
            resp = await client.get(url, params=params)
            data = resp.json()
            messages = data.get("messages", [])
            return [ATPMessage.from_dict(m) for m in messages]

    async def close(self) -> None:
        await self._transport.close()
