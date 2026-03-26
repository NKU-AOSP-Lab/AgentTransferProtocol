"""CLI commands for managing agent credentials."""

import click


@click.group("agent")
def agent_group():
    """Manage agent credentials."""
    pass


@agent_group.command("register")
@click.argument("agent_id")
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True, help="Agent password")
def register_cmd(agent_id, password):
    """Register a new agent on this server."""
    from atp.storage.agents import AgentStore
    from atp.storage.config import ConfigStorage

    config = ConfigStorage()
    config.ensure_dirs()
    db_path = config.config_dir / "data" / "messages.db"

    store = AgentStore(db_path)
    store.init_db()

    try:
        record = store.register(agent_id, password)
        click.echo(f"Agent registered: {agent_id}")
    except Exception as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)


@agent_group.command("list")
def list_cmd():
    """List registered agents."""
    from atp.storage.agents import AgentStore
    from atp.storage.config import ConfigStorage

    config = ConfigStorage()
    db_path = config.config_dir / "data" / "messages.db"

    store = AgentStore(db_path)
    store.init_db()

    agents = store.list_agents()
    if not agents:
        click.echo("No agents registered.")
        return
    for a in agents:
        click.echo(f"  {a.agent_id}")


@agent_group.command("remove")
@click.argument("agent_id")
def remove_cmd(agent_id):
    """Remove a registered agent."""
    from atp.storage.agents import AgentStore
    from atp.storage.config import ConfigStorage

    config = ConfigStorage()
    db_path = config.config_dir / "data" / "messages.db"

    store = AgentStore(db_path)
    store.init_db()

    if store.remove(agent_id):
        click.echo(f"Agent removed: {agent_id}")
    else:
        click.echo(f"Agent not found: {agent_id}")
