import asyncio
import json
import time
import click


@click.command("inspect")
@click.argument("nonce")
@click.option("--server", default="localhost:7443", help="Server URL (host:port)")
@click.option("--local", is_flag=True, help="Disable TLS verification")
@click.option("--output", type=click.Choice(["json", "text"]), default="text")
def inspect_cmd(nonce, server, local, output):
    """Inspect a specific message by nonce."""
    import httpx

    async def _inspect():
        parts = server.split(":")
        host = parts[0]
        port = parts[1] if len(parts) > 1 else "7443"

        base = f"https://{host}:{port}"
        async with httpx.AsyncClient(verify=not local) as client:
            resp = await client.get(f"{base}/.well-known/atp/v1/inspect", params={"nonce": nonce})
            return resp.status_code, resp.json()

    try:
        status_code, data = asyncio.run(_inspect())
    except Exception as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)

    if status_code == 404:
        click.echo(f"Message {nonce} not found.")
        raise SystemExit(1)

    if output == "json":
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"Nonce:       {data.get('nonce')}")
    click.echo(f"From:        {data.get('from')}")
    click.echo(f"To:          {data.get('to')}")
    click.echo(f"Status:      {data.get('status')}")

    created = data.get("created_at", 0)
    if created:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(created, tz=timezone.utc)
        click.echo(f"Created:     {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    updated = data.get("updated_at", 0)
    if updated:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(updated, tz=timezone.utc)
        click.echo(f"Updated:     {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    retry = data.get("retry_count", 0)
    if retry:
        click.echo(f"Retries:     {retry}")

    next_retry = data.get("next_retry_at")
    if next_retry:
        remaining = next_retry - int(time.time())
        if remaining > 0:
            click.echo(f"Next retry:  in {remaining}s")
        else:
            click.echo(f"Next retry:  pending")

    error = data.get("error")
    if error:
        click.echo(f"Error:       {error}")
