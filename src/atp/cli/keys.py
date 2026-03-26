"""CLI commands for managing Ed25519 key pairs."""

import click


@click.group("keys")
def keys_group():
    """Manage Ed25519 key pairs."""
    pass


@keys_group.command("generate")
@click.option("--selector", default="default", help="Key selector name")
def generate_cmd(selector):
    """Generate a new Ed25519 key pair."""
    from atp.storage.config import ConfigStorage
    from atp.storage.keys import KeyStorage

    config = ConfigStorage()
    config.ensure_dirs()
    keys = KeyStorage(config.config_dir / "keys")
    info = keys.generate(selector)
    click.echo("Key pair generated:")
    click.echo(f"  Selector:    {info.selector}")
    click.echo(f"  Private key: {info.private_key_path}")
    click.echo(f"  Public key:  {info.public_key_path}")


@keys_group.command("show")
@click.option("--selector", default="default")
@click.option("--public", is_flag=True, help="Show public key only")
def show_cmd(selector, public):
    """Show key information."""
    from atp.storage.config import ConfigStorage
    from atp.storage.keys import KeyStorage

    keys = KeyStorage(ConfigStorage().config_dir / "keys")
    pub_b64 = keys.get_public_key_b64(selector)
    click.echo(f"Selector: {selector}")
    click.echo(f"Public key (base64): {pub_b64}")
    if not public:
        click.echo(f"Private key path: {keys._keys_dir / f'{selector}.key'}")


@keys_group.command("list")
def list_cmd():
    """List all key pairs."""
    from atp.storage.config import ConfigStorage
    from atp.storage.keys import KeyStorage

    keys = KeyStorage(ConfigStorage().config_dir / "keys")
    key_list = keys.list_keys()
    if not key_list:
        click.echo("No keys found.")
        return
    for k in key_list:
        click.echo(f"  {k.selector}: created {k.created_at}")


@keys_group.command("rotate")
@click.option("--old-selector", default="default")
@click.option("--new-selector", required=True)
def rotate_cmd(old_selector, new_selector):
    """Rotate to a new key pair."""
    from atp.storage.config import ConfigStorage
    from atp.storage.keys import KeyStorage

    keys = KeyStorage(ConfigStorage().config_dir / "keys")
    info = keys.rotate(old_selector, new_selector)
    click.echo(f"New key pair generated: {info.selector}")
    click.echo(f"Old key '{old_selector}' preserved.")
