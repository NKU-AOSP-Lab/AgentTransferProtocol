import asyncio
import json
import click


@click.command("status")
@click.option("--server", default="localhost:7443", help="Server URL (host:port)")
@click.option("--local", is_flag=True, help="Disable TLS verification")
@click.option("--output", type=click.Choice(["json", "text"]), default="text")
def status_cmd(server, local, output):
    """Show ATP server status and metrics."""
    import httpx

    async def _status():
        parts = server.split(":")
        host = parts[0]
        port = parts[1] if len(parts) > 1 else "7443"

        base = f"https://{host}:{port}"
        async with httpx.AsyncClient(verify=not local) as client:
            # Get stats
            stats_resp = await client.get(f"{base}/.well-known/atp/v1/stats")
            return stats_resp.json()

    try:
        data = asyncio.run(_status())
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
