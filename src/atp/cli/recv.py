"""CLI command for receiving ATP messages."""

import asyncio
import json

import click


@click.command("recv")
@click.option("--agent-id", default=None, help="Agent ID to receive for")
@click.option("--password", "-P", default=None, help="Agent password for authentication")
@click.option("--server", default=None, help="Server URL (host:port)")
@click.option("--local", is_flag=True, help="Use local mode")
@click.option("--wait", is_flag=True, help="Wait for messages")
@click.option("--limit", default=50, type=int)
@click.option("--output", type=click.Choice(["json", "text"]), default="json")
def recv_cmd(agent_id, password, server, local, wait, limit, output):
    """Receive ATP messages."""
    from atp.client.client import ATPClient
    from atp.storage.config import ConfigStorage

    if agent_id is None:
        config = ConfigStorage().load()
        agent_id = config.agent_id
        if not agent_id:
            raise click.ClickException(
                "No agent_id specified. Use --agent-id or set in config."
            )

    async def _recv():
        client = ATPClient(agent_id=agent_id, password=password, server_url=server, local_mode=local)
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
