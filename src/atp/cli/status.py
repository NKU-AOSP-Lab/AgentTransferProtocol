import asyncio
import json
import click


@click.command("status")
@click.option("--server", required=True, help="Server address (host:port)")
@click.option("--admin-token", required=True, help="Admin bearer token for server access")
@click.option("--no-verify", is_flag=True, help="Skip TLS certificate verification")
@click.option("--output", type=click.Choice(["json", "text"]), default="text")
def status_cmd(server, admin_token, no_verify, output):
    """Show ATP server status and metrics."""
    import httpx
    from atp.client.transport import parse_server_url

    base_url, is_https = parse_server_url(server)

    # Warn if HTTP
    if not is_https and not no_verify:
        click.echo("WARNING: Connection is not encrypted.")
        if not click.confirm("Continue?"):
            raise SystemExit(0)

    async def _status():
        verify = True
        if no_verify or not is_https:
            verify = False

        headers = {"Authorization": f"Bearer {admin_token}"}
        async with httpx.AsyncClient(verify=verify) as client:
            stats_resp = await client.get(f"{base_url}/.well-known/atp/v1/stats", headers=headers)
            if stats_resp.status_code != 200:
                click.echo(f"Error: server returned {stats_resp.status_code}")
                try:
                    detail = stats_resp.json().get("error", "")
                    if detail:
                        click.echo(f"  {detail}")
                except Exception:
                    pass
                raise SystemExit(1)
            return stats_resp.json()

    try:
        data = asyncio.run(_status())
    except SystemExit:
        raise
    except Exception as e:
        click.echo(f"Error connecting to server: {e}")
        raise SystemExit(1)

    if output == "json":
        click.echo(json.dumps(data, indent=2))
        return

    # Pretty text output
    domain = data.get("domain", "unknown")
    uptime = data.get("uptime", 0)
    hours, remainder = divmod(uptime, 3600)
    minutes, seconds = divmod(remainder, 60)

    click.echo(f"ATP Server: {domain}")
    click.echo(f"  Uptime:     {hours}h {minutes}m {seconds}s")
    click.echo()

    msgs = data.get("messages", {})
    click.echo("Messages:")
    click.echo(f"  Received:       {msgs.get('received', 0)}")
    click.echo(f"  Delivered:      {msgs.get('delivered_local', 0)}")
    click.echo(f"  Forwarded:      {msgs.get('forwarded', 0)}")
    click.echo(f"  Success:        {msgs.get('delivery_success', 0)}")
    click.echo(f"  Failed:         {msgs.get('delivery_failed', 0)}")
    click.echo(f"  Bounced:        {msgs.get('bounced', 0)}")
    click.echo()

    queue = data.get("queue", {})
    click.echo("Queue:")
    click.echo(f"  Queued:         {queue.get('queued', 0)}")
    click.echo(f"  Delivering:     {queue.get('delivering', 0)}")
    click.echo(f"  Delivered:      {queue.get('delivered', 0)}")
    click.echo(f"  Failed:         {queue.get('failed', 0)}")
    click.echo(f"  Bounced:        {queue.get('bounced', 0)}")
    click.echo()

    sec = data.get("security", {})
    click.echo("Security:")
    click.echo(f"  ATS Pass:       {sec.get('ats_pass', 0)}")
    click.echo(f"  ATS Fail:       {sec.get('ats_fail', 0)}")
    click.echo(f"  ATK Pass:       {sec.get('atk_pass', 0)}")
    click.echo(f"  ATK Fail:       {sec.get('atk_fail', 0)}")
    click.echo(f"  Replay Blocked: {sec.get('replay_blocked', 0)}")
    click.echo()

    agents = data.get("agents", [])
    if agents:
        click.echo(f"Agents ({len(agents)}):")
        for a in agents:
            click.echo(f"  {a}")
