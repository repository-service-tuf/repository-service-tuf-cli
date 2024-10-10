# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT


"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

"""
from typing import Optional

from repository_service_tuf.cli import click, rstuf


def _set_settings(context: click.Context, api_server: Optional[str]):
    """Set context.obj['settings'] attributes."""
    settings = context.obj["settings"]
    if api_server:
        settings.SERVER = api_server


@rstuf.group()  # type: ignore
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.pass_context
def admin(context: click.Context, api_server: Optional[str]):
    """Administrative Commands"""
    # Because of tests it has to be in a separate function.
    _set_settings(context, api_server)  # pragma: no cover
