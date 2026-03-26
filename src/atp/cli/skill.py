"""CLI command to output the ATP skill prompt for AI agents."""

from pathlib import Path

import click


@click.command("skill")
def skill_cmd():
    """Print the ATP skill prompt for teaching AI agents how to use ATP."""
    skill_path = Path(__file__).parent.parent / "skill.md"
    click.echo(skill_path.read_text(encoding="utf-8"))
