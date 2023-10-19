# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from rich.console import Console  # type: ignore

from repository_service_tuf.cli import click
from repository_service_tuf.cli.key import key
from repository_service_tuf.helpers.tuf import (
    RSTUFKey,
    get_key,
    print_key_table,
)

console = Console()


@key.command()
def info() -> None:
    """Show key information"""

    rstuf_key: RSTUFKey = get_key()
    if rstuf_key.error:
        console.print(rstuf_key.error)
        raise click.ClickException("Failed to load the Key")

    print_key_table(rstuf_key)
