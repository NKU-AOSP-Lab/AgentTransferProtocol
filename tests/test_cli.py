"""Tests for the ATP CLI."""

import pytest
from click.testing import CliRunner

from atp.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "ATP" in result.output


def test_cli_version(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0a1" in result.output


def test_keys_help(runner):
    result = runner.invoke(cli, ["keys", "--help"])
    assert result.exit_code == 0


def test_dns_help(runner):
    result = runner.invoke(cli, ["dns", "--help"])
    assert result.exit_code == 0


def test_server_help(runner):
    result = runner.invoke(cli, ["server", "--help"])
    assert result.exit_code == 0


def test_send_help(runner):
    result = runner.invoke(cli, ["send", "--help"])
    assert result.exit_code == 0


def test_recv_help(runner):
    result = runner.invoke(cli, ["recv", "--help"])
    assert result.exit_code == 0


def test_keys_generate(runner, tmp_path, monkeypatch):
    """Test key generation via CLI."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # On Windows, also patch Path.home()
    import pathlib

    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    result = runner.invoke(cli, ["keys", "generate", "--selector", "test"])
    assert result.exit_code == 0
    assert "generated" in result.output.lower() or "Key pair" in result.output


def test_status_help(runner):
    result = runner.invoke(cli, ["status", "--help"])
    assert result.exit_code == 0


def test_inspect_help(runner):
    result = runner.invoke(cli, ["inspect", "--help"])
    assert result.exit_code == 0


def test_agent_help(runner):
    result = runner.invoke(cli, ["agent", "--help"])
    assert result.exit_code == 0
    assert "agent" in result.output.lower()


def test_agent_register(runner, tmp_path, monkeypatch):
    """Test agent registration via CLI."""
    import pathlib

    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    result = runner.invoke(cli, ["agent", "register", "alice@example.com", "-p", "secret123"], input="secret123\n")
    assert result.exit_code == 0
    assert "Agent registered" in result.output


def test_agent_list(runner, tmp_path, monkeypatch):
    """Test agent listing via CLI."""
    import pathlib

    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    # First register an agent
    runner.invoke(cli, ["agent", "register", "alice@example.com", "-p", "secret123"], input="secret123\n")
    # Then list
    result = runner.invoke(cli, ["agent", "list"])
    assert result.exit_code == 0
    assert "alice@example.com" in result.output


def test_agent_remove(runner, tmp_path, monkeypatch):
    """Test agent removal via CLI."""
    import pathlib

    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    # Register then remove
    runner.invoke(cli, ["agent", "register", "alice@example.com", "-p", "secret123"], input="secret123\n")
    result = runner.invoke(cli, ["agent", "remove", "alice@example.com"])
    assert result.exit_code == 0
    assert "Agent removed" in result.output


def test_dns_generate(runner, tmp_path, monkeypatch):
    """Test DNS record generation."""
    import pathlib

    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    # First generate a key
    runner.invoke(cli, ["keys", "generate"])
    # Then generate DNS records
    result = runner.invoke(
        cli, ["dns", "generate", "--domain", "example.com", "--ip", "1.2.3.4"]
    )
    assert result.exit_code == 0
    assert "_atp.example.com" in result.output
    assert "ats._atp.example.com" in result.output
    assert "atk._atp.example.com" in result.output
