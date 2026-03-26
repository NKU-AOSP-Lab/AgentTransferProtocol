"""CLI command to output the ATP skill prompt for AI agents."""

import click

SKILL_TEXT = """\
# ATP: Agent Transfer Protocol

You can send and receive messages to other agents across the Internet using the `atp` CLI tool.

## Prerequisites

Before sending messages, you need:
1. The address of your ATP server (e.g. `atp.example.com` or `atp.example.com:7443`)
2. A registered agent identity and password

## Registering on a Server

```bash
atp agent register <your-agent-name> --server <server-address> -p <your-password>
```

Example:
```bash
atp agent register mybot --server atp.example.com -p mypassword
```

This registers `mybot@atp.example.com` on the server. The `@domain` is added automatically.

## Sending a Message

```bash
atp send <recipient> --from <your-agent-name> --password <your-password> --server <server-address> --body "Your message"
```

Example:
```bash
atp send assistant@remote.org --from mybot --password mypass --server atp.example.com --body "Hello"
```

For structured data, use `--payload` with a JSON file:
```bash
atp send target@remote.org --from mybot --password mypass --server atp.example.com --payload data.json
```

Output: `{"status": "accepted", "nonce": "msg-...", "timestamp": ...}`

## Receiving Messages

```bash
atp recv --agent-id <your-agent-name> --password <your-password> --server <server-address>
```

Add `--wait` to block until messages arrive:
```bash
atp recv --agent-id mybot --password mypass --server atp.example.com --wait
```

Output: JSON array of messages with `from`, `to`, `payload`, `nonce` fields.

## Other Commands

- `atp status --server <addr>` - server status and metrics
- `atp inspect <nonce> --server <addr>` - track a specific message

## Notes

- `--server` defaults to HTTPS on port 7443. Use `http://` prefix for plaintext.
- Agent names without `@` are auto-completed with the server domain.
- `--no-verify` skips TLS certificate verification.
- All output is JSON by default.
- Messages are asynchronous: send returns a nonce, use inspect to track.
"""


@click.command("skill")
def skill_cmd():
    """Print the ATP skill prompt for teaching AI agents how to use ATP."""
    click.echo(SKILL_TEXT)
