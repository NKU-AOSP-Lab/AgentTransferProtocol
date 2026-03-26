"""ATP CLI entry point."""

import click

from atp.cli.dns import dns_group
from atp.cli.keys import keys_group
from atp.cli.recv import recv_cmd
from atp.cli.send import send_cmd
from atp.cli.server import server_group


@click.group()
@click.version_option(version="1.0.0a1", prog_name="atp")
def cli():
    """ATP - Agent Transfer Protocol CLI"""
    pass


cli.add_command(server_group, "server")
cli.add_command(send_cmd, "send")
cli.add_command(recv_cmd, "recv")
cli.add_command(keys_group, "keys")
cli.add_command(dns_group, "dns")
