"""CLI commands for managing agent credentials."""

import asyncio
import json

import click


@click.group("agent")
def agent_group():
    """Manage agent credentials."""
    pass


@agent_group.command("register")
@click.argument("agent_id")
@click.option("--server", required=True, help="Server address (host:port)")
@click.option("--no-verify", is_flag=True, help="Skip TLS certificate verification")
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
def register_cmd(agent_id, server, no_verify, password):
    """Register a new agent on an ATP server.

    AGENT_ID is the short name (e.g. 'mybot'). The server will
    auto-complete it with its own domain (e.g. 'mybot@example.com').
    """
    import httpx
    from atp.client.transport import parse_server_url

    base_url, is_https = parse_server_url(server)

    # Don't auto-complete agent_id on the client side — the server
    # knows its own domain and will normalize the ID. Sending the
    # short form avoids binding to the server address (which may be
    # an IP or localhost, not the ATP domain).

    # Warn if HTTP
    if not is_https:
        if not no_verify:
            click.echo("WARNING: Connection is not encrypted.")
            if not click.confirm("Continue?"):
                raise SystemExit(0)

    async def _register():
        verify = True
        if no_verify or not is_https:
            verify = False

        try:
            async with httpx.AsyncClient(verify=verify) as client:
                url = f"{base_url}/.well-known/atp/v1/register"
                resp = await client.post(url, json={"agent_id": agent_id, "password": password})
                return resp.status_code, resp.json()
        except httpx.ConnectError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e):
                if not no_verify:
                    click.echo("WARNING: Certificate verification failed.")
                    if click.confirm("Continue without verification?"):
                        async with httpx.AsyncClient(verify=False) as client2:
                            resp = await client2.post(url, json={"agent_id": agent_id, "password": password})
                            return resp.status_code, resp.json()
                raise
            raise

    try:
        status_code, data = asyncio.run(_register())
    except Exception as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)

    if status_code == 201:
        click.echo(f"Agent registered: {data.get('agent_id', agent_id)}")
    else:
        click.echo(f"Error: {data.get('error', 'unknown')}")
        raise SystemExit(1)


@agent_group.command("list")
@click.option("--server", required=True, help="Server address (host:port)")
@click.option("--admin-token", required=True, help="Admin bearer token for server access")
@click.option("--no-verify", is_flag=True, help="Skip TLS certificate verification")
def list_cmd(server, admin_token, no_verify):
    """List registered agents on a remote ATP server."""
    import httpx
    from atp.client.transport import parse_server_url

    base_url, is_https = parse_server_url(server)

    # Warn if HTTP
    if not is_https and not no_verify:
        click.echo("WARNING: Connection is not encrypted.")
        if not click.confirm("Continue?"):
            raise SystemExit(0)

    async def _list():
        verify = True
        if no_verify or not is_https:
            verify = False

        headers = {"Authorization": f"Bearer {admin_token}"}
        try:
            async with httpx.AsyncClient(verify=verify) as client:
                url = f"{base_url}/.well-known/atp/v1/agents"
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    click.echo(f"Error: server returned {resp.status_code}")
                    try:
                        detail = resp.json().get("error", "")
                        if detail:
                            click.echo(f"  {detail}")
                    except Exception:
                        pass
                    raise SystemExit(1)
                return resp.json()
        except httpx.ConnectError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e):
                if not no_verify:
                    click.echo("WARNING: Certificate verification failed.")
                    if click.confirm("Continue without verification?"):
                        async with httpx.AsyncClient(verify=False) as client2:
                            resp = await client2.get(url, headers=headers)
                            if resp.status_code != 200:
                                click.echo(f"Error: server returned {resp.status_code}")
                                raise SystemExit(1)
                            return resp.json()
                raise
            raise

    try:
        data = asyncio.run(_list())
    except SystemExit:
        raise
    except Exception as e:
        click.echo(f"Error connecting to server: {e}")
        raise SystemExit(1)

    agents = data.get("agents", [])
    if not agents:
        click.echo("No agents registered.")
        return
    for a in agents:
        click.echo(f"  {a}")
