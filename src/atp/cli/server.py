"""CLI commands for managing the ATP server."""

import click


@click.group("server")
def server_group():
    """Manage ATP server."""
    pass


@server_group.command("start")
@click.option("--domain", required=True, help="Server domain name")
@click.option("--port", default=7443, type=int, help="Listen port")
@click.option("--host", default="0.0.0.0", help="Bind address")
@click.option("--no-verify", is_flag=True, help="Skip TLS verification for outbound connections")
@click.option("--cert", type=click.Path(), help="TLS certificate path")
@click.option("--key", "tls_key", type=click.Path(), help="TLS private key path")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
)
def start_cmd(domain, port, host, no_verify, cert, tls_key, log_level):
    """Start the ATP server."""
    from atp.server.app import ATPServer
    from atp.server.config import RuntimeServerConfig
    from atp.storage.config import ConfigStorage

    config_storage = ConfigStorage()
    atp_config = config_storage.load()

    cli_args = {
        "domain": domain,
        "port": port,
        "host": host,
        "local": no_verify,
        "cert": cert,
        "key": tls_key,
        "log_level": log_level,
    }
    runtime_config = RuntimeServerConfig.from_cli_and_config(cli_args, atp_config)

    server = ATPServer(runtime_config)
    click.echo(f"Starting ATP Server: {domain} on {host}:{port}")
    server.run()
