# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from repository_service_tuf.cli import click, rstuf


@rstuf.group()  # type: ignore
def key():
    """Cryptographic Key Commands"""

    DEPRECATION_WARNING = """
    This command is deprecated and will be removed in a future release.

    Please use `key` command only if you will be using the `admin-legacy`.
    commands.
    """
    click.echo(click.style(DEPRECATION_WARNING, bold=True, fg="red"))
    click.pause()
