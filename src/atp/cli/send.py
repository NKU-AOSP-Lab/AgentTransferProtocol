"""CLI command for sending ATP messages."""

import asyncio
import json

import click


@click.command("send")
@click.argument("to")
@click.option("--from", "from_id", default=None, help="Sender agent ID")
@click.option("--body", "-b", default=None, help="Message body")
@click.option("--subject", "-s", default=None, help="Message subject")
@click.option("--payload", "-p", type=click.Path(exists=True), help="JSON payload file")
@click.option("--server", default=None, help="Server URL (host:port)")
@click.option("--local", is_flag=True, help="Use local mode (no TLS verify)")
@click.option("--output", type=click.Choice(["json", "text"]), default="json")
def send_cmd(to, from_id, body, subject, payload, server, local, output):
    """Send an ATP message."""
    from atp.client.client import ATPClient
    from atp.storage.config import ConfigStorage

    if from_id is None:
        config = ConfigStorage().load()
        from_id = config.agent_id
        if not from_id:
            raise click.ClickException(
                "No sender specified. Use --from or set agent_id in config."
            )

    # Build payload
    msg_payload: dict = {}
    if payload:
        with open(payload) as f:
            msg_payload = json.load(f)
    elif body or subject:
        if body:
            msg_payload["body"] = body
        if subject:
            msg_payload["subject"] = subject

    async def _send():
        client = ATPClient(agent_id=from_id, server_url=server, local_mode=local)
        try:
            result = await client.send(to, payload=msg_payload)
            return result
        finally:
            await client.close()

    result = asyncio.run(_send())

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        if result.get("status") == "accepted":
            click.echo(f"Message sent. nonce={result['nonce']}")
        else:
            click.echo(f"Error: {result.get('error', 'unknown')}")
