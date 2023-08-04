# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from rich import prompt, table
from rich.console import Console  # type: ignore

from repository_service_tuf.cli import click
from repository_service_tuf.cli.key import key
from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers.tuf import load_key

console = Console()


@click.option(
    "--show-private",
    help=(
        "Show the private key. WARNING: use private key information carefully."
    ),
    default=False,
    show_default=True,
    is_flag=True,
)
@key.command()
def info(show_private: bool) -> None:
    """Show key information"""

    keytype: str = prompt.Prompt.ask(
        "\nChoose key type",
        choices=KeyType.get_all_members(),
        default=KeyType.KEY_TYPE_ED25519.value,
    )

    filepath: str = prompt.Prompt.ask("Enter the key's [green]filename[/]")

    password = click.prompt("Enter the private key password", hide_input=True)

    key = load_key(filepath, keytype, password, "")
    if key.error:
        console.print(key.error)
        raise click.ClickException("Failed to load the Key")

    key_table = table.Table()
    key_table.add_column("Key ID", justify="center")
    key_table.add_column("Key Type", justify="center")
    key_table.add_column("Public Key", justify="center")
    row_items = [key.key["keyid"], key.key["keytype"], key.key["keyval"]["public"]]
    if show_private:
        key_table.add_column(
            "Private Key", justify="center", style="red", no_wrap=True
        )
        row_items.append(key.key["keyval"]["private"])

    key_table.add_row(*row_items)


    console.print(key_table)
