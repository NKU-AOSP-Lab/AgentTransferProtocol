"""CLI command for receiving ATP messages."""

import asyncio
import json

import click


@click.command("recv")
@click.option("--agent-id", default=None, help="Agent ID to receive for")
@click.option("--password", "-P", default=None, help="Agent password for authentication")
@click.option("--server", required=True, help="Server address (host:port)")
@click.option("--no-verify", is_flag=True, help="Skip TLS certificate verification")
@click.option("--wait", is_flag=True, help="Wait for messages")
@click.option("--limit", default=50, type=int)
@click.option("--output", type=click.Choice(["json", "text"]), default="json")
def recv_cmd(agent_id, password, server, no_verify, wait, limit, output):
    """Receive ATP messages."""
    from atp.client.client import ATPClient
    from atp.client.transport import parse_server_url
    from atp.storage.config import ConfigStorage

    if agent_id is None:
        config = ConfigStorage().load()
        agent_id = config.agent_id
        if not agent_id:
            raise click.ClickException(
                "No agent_id specified. Use --agent-id or set in config."
            )

    if "@" not in agent_id:
        raise click.ClickException(
            f"Agent ID '{agent_id}' must include domain (e.g. 'mybot@example.com')."
        )

    # Warn if HTTP
    _, is_https = parse_server_url(server)
    if not is_https and not no_verify:
        click.echo("WARNING: Connection is not encrypted.")
        if not click.confirm("Continue?"):
            raise SystemExit(0)

    async def _recv():
        client = ATPClient(agent_id=agent_id, password=password, server=server, no_verify=no_verify)
        try:
            messages = await client.recv(limit=limit, wait=wait)
            return messages
        finally:
            await client.close()

    messages = asyncio.run(_recv())

    if output == "json":
        click.echo(json.dumps([m.to_dict() for m in messages], indent=2))
    else:
        if not messages:
            click.echo("No messages.")
        for m in messages:
            click.echo(f"[{m.nonce}] {m.from_id} -> {m.to_id}: {m.payload}")
