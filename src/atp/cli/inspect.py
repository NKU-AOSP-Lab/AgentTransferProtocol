import asyncio
import json
import time
import click


@click.command("inspect")
@click.argument("nonce")
@click.option("--server", required=True, help="Server address (host:port)")
@click.option("--admin-token", required=True, help="Admin bearer token for server access")
@click.option("--no-verify", is_flag=True, help="Skip TLS certificate verification")
@click.option("--output", type=click.Choice(["json", "text"]), default="text")
def inspect_cmd(nonce, server, admin_token, no_verify, output):
    """Inspect a specific message by nonce."""
    import httpx
    from atp.client.transport import parse_server_url

    base_url, is_https = parse_server_url(server)

    # Warn if HTTP
    if not is_https and not no_verify:
        click.echo("WARNING: Connection is not encrypted.")
        if not click.confirm("Continue?"):
            raise SystemExit(0)

    async def _inspect():
        verify = True
        if no_verify or not is_https:
            verify = False

        headers = {"Authorization": f"Bearer {admin_token}"}
        async with httpx.AsyncClient(verify=verify) as client:
            resp = await client.get(f"{base_url}/.well-known/atp/v1/inspect", params={"nonce": nonce}, headers=headers)
            if resp.status_code not in (200, 404):
                click.echo(f"Error: server returned {resp.status_code}")
                try:
                    detail = resp.json().get("error", "")
                    if detail:
                        click.echo(f"  {detail}")
                except Exception:
                    pass
                raise SystemExit(1)
            return resp.status_code, resp.json()

    try:
        status_code, data = asyncio.run(_inspect())
    except SystemExit:
        raise
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
