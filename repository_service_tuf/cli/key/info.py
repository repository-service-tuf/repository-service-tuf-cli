# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from rich import prompt
from rich.console import Console  # type: ignore

from repository_service_tuf.cli import click
from repository_service_tuf.cli.key import key
from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers.tuf import (
    RSTUFKey,
    load_key,
    print_key_table,
)

console = Console()


def _get_key() -> RSTUFKey:
    keytype: str = prompt.Prompt.ask(
        "\nChoose key type",
        choices=KeyType.get_all_members(),
        default=KeyType.KEY_TYPE_ED25519.value,
    )
    filepath: str = prompt.Prompt.ask(
        "Enter the private key's [green]file name[/]"
    )
    password: str = click.prompt(
        "Enter the private key password", hide_input=True
    )

    return load_key(filepath, keytype, password, "")


@key.command()
def info() -> None:
    """Show key information"""

    rstuf_key = _get_key()
    if rstuf_key.error:
        console.print(rstuf_key.error)
        raise click.ClickException("Failed to load the Key")
    print_key_table(rstuf_key)
