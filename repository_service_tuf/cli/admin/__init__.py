# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT


"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

"""
from typing import Optional

from repository_service_tuf.cli import click, console, rstuf


def _set_settings(
    context: click.Context, api_server: Optional[str], offline: bool
):
    """Set context.obj['settings'] attributes."""
    if api_server and offline:
        err = "Using both '--api-server' and '--offline' is not allowed"
        raise click.ClickException(err)

    settings = context.obj["settings"]
    if api_server:
        settings.SERVER = api_server

    if offline:
        console.print("Running command in offline mode...\n")

    settings.OFFLINE = offline


@rstuf.group()  # type: ignore
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.option(
    "--offline",
    help=(
        "Run command offline not communicating with RSTUF API. RSTUF SERVER "
        "configuration and '--api-server' will be ignored."
    ),
    default=False,
    is_flag=True,
    required=False,
)
@click.pass_context
def admin(
    context: click.Context, api_server: Optional[str], offline: bool
):  # pragma: no cover
    """Administrative Commands"""
    # Because of tests it has to be in a separate function.
    _set_settings(context, api_server, offline)


@admin.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """
