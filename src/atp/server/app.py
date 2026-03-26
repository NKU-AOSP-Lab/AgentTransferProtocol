"""ATP server application — wires together all components and runs via uvicorn."""

import logging

import uvicorn
from starlette.applications import Starlette

from atp.server.config import RuntimeServerConfig
from atp.server.routes import get_routes
from atp.server.queue import MessageQueue
from atp.server.delivery import DeliveryManager
from atp.security.ats import ATSVerifier
from atp.security.atk import ATKVerifier
from atp.security.replay import ReplayGuard
from atp.security.tls import TLSConfig
from atp.discovery.dns import DNSResolver
from atp.discovery.local import LocalResolver, CompositeResolver
from atp.storage.config import ConfigStorage
from atp.storage.keys import KeyStorage
from atp.storage.messages import MessageStore
from atp.core.signature import Signer

logger = logging.getLogger("atp.server")


class ATPServer:
    def __init__(self, config: RuntimeServerConfig):
        self.config = config
        self.app: Starlette | None = None
        self.queue: MessageQueue | None = None
        self.ats_verifier: ATSVerifier | None = None
        self.atk_verifier: ATKVerifier | None = None
        self.replay_guard: ReplayGuard | None = None
        self.delivery_manager: DeliveryManager | None = None
        self.signer: Signer | None = None
        self._config_storage: ConfigStorage | None = None

    def _setup(self) -> None:
        """Initialize all components."""
        logging.basicConfig(level=getattr(logging, self.config.log_level.upper(), logging.INFO))

        self._config_storage = ConfigStorage()
        self._config_storage.ensure_dirs()
        config_dir = self._config_storage.config_dir

        # Message store
        db_path = config_dir / "data" / "messages.db"
        message_store = MessageStore(db_path)
        message_store.init_db()
        self.queue = MessageQueue(message_store)

        # DNS resolver
        dns_resolver = DNSResolver()
        if self.config.local_mode:
            local = LocalResolver(
                peers_path=self.config.peers_file,
                dns_override_path=self.config.dns_override_file,
            )
            resolver = CompositeResolver(local, dns_resolver)
        else:
            resolver = dns_resolver

        # Security
        self.ats_verifier = ATSVerifier(resolver)
        self.atk_verifier = ATKVerifier(resolver)
        self.replay_guard = ReplayGuard(max_age_seconds=self.config.replay_max_age)

        # Signer
        key_storage = KeyStorage(config_dir / "keys")
        try:
            private_key = key_storage.load_private_key(self.config.key_selector)
        except Exception:
            logger.info(f"No key found for selector '{self.config.key_selector}', generating...")
            key_storage.generate(self.config.key_selector)
            private_key = key_storage.load_private_key(self.config.key_selector)
        self.signer = Signer(private_key, self.config.key_selector, self.config.domain)

        # Transport (lazy import to avoid circular deps)
        from atp.client.transport import HTTPTransport

        transport = HTTPTransport(tls_verify=not self.config.local_mode)

        # Delivery manager
        self.delivery_manager = DeliveryManager(
            message_store=message_store,
            dns_resolver=resolver,
            transport=transport,
            signer=self.signer,
            server_domain=self.config.domain,
            max_retries=self.config.retry_max_attempts,
        )

        # Starlette app
        self.app = Starlette(
            routes=get_routes(),
            on_startup=[self._on_startup],
            on_shutdown=[self._on_shutdown],
        )
        self.app.state.server = self

    async def _on_startup(self) -> None:
        await self.delivery_manager.start()
        logger.info(f"ATP Server started: {self.config.domain} on port {self.config.port}")

    async def _on_shutdown(self) -> None:
        await self.delivery_manager.stop()
        logger.info("ATP Server stopped")

    def run(self) -> None:
        """Blocking entry point."""
        self._setup()

        ssl_context = None
        if self.config.tls_cert_path and self.config.tls_key_path:
            ssl_context = TLSConfig.create_server_context(
                self.config.tls_cert_path, self.config.tls_key_path
            )

        uvicorn.run(
            self.app,
            host=self.config.host,
            port=self.config.port,
            ssl=ssl_context,
            log_level=self.config.log_level.lower(),
        )
