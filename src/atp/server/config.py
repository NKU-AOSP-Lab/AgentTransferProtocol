"""Runtime server configuration — merges CLI args with config file defaults."""

from dataclasses import dataclass

from atp.storage.config import ATPConfig


@dataclass
class RuntimeServerConfig:
    domain: str
    port: int = 7443
    host: str = "0.0.0.0"
    tls_cert_path: str = ""
    tls_key_path: str = ""
    local_mode: bool = False
    peers_file: str | None = None
    dns_override_file: str | None = None
    key_selector: str = "default"
    max_message_size: int = 1_048_576  # 1 MB
    replay_max_age: int = 300
    retry_max_attempts: int = 6
    log_level: str = "INFO"

    @classmethod
    def from_cli_and_config(cls, cli_args: dict, atp_config: ATPConfig) -> "RuntimeServerConfig":
        """Merge: CLI args override config file values override defaults.

        cli_args keys: domain, port, host, local, peers, cert, key, log_level
        """
        # Start with config-file values
        domain = atp_config.server.domain
        port = atp_config.server.port
        host = "0.0.0.0"
        tls_cert_path = atp_config.server.tls_cert
        tls_key_path = atp_config.server.tls_key
        local_mode = atp_config.local_mode
        peers_file = atp_config.peers_file or None
        dns_override_file = atp_config.dns_override_file or None
        key_selector = atp_config.key_selector
        log_level = "INFO"

        # CLI overrides (only if present and non-None)
        if cli_args.get("domain"):
            domain = cli_args["domain"]
        if cli_args.get("port") is not None:
            port = cli_args["port"]
        if cli_args.get("host"):
            host = cli_args["host"]
        if cli_args.get("cert"):
            tls_cert_path = cli_args["cert"]
        if cli_args.get("key"):
            tls_key_path = cli_args["key"]
        if cli_args.get("local") is not None:
            local_mode = cli_args["local"]
        if cli_args.get("peers"):
            peers_file = cli_args["peers"]
        if cli_args.get("log_level"):
            log_level = cli_args["log_level"]

        return cls(
            domain=domain,
            port=port,
            host=host,
            tls_cert_path=tls_cert_path,
            tls_key_path=tls_key_path,
            local_mode=local_mode,
            peers_file=peers_file,
            dns_override_file=dns_override_file,
            key_selector=key_selector,
            log_level=log_level,
        )
