# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT


"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

"""
from typing import Optional

from repository_service_tuf.cli import click, rstuf

HEADERS_EXAMPLE = (
    "'Authorization: Bearer <token>, Content-Type: application/json'"
)


def _set_settings(
    context: click.Context, api_server: Optional[str], headers: Optional[str]
):
    """Set context.obj['settings'] attributes."""
    settings = context.obj["settings"]
    if api_server:
        settings.SERVER = api_server
    if headers:
        try:
            settings.HEADERS = dict(
                (key.strip(), value.strip())
                for key, value in (
                    header.split(":", 1) for header in headers.split(",")
                )
            )
        except ValueError:
            raise click.ClickException(
                f"Invalid headers format. Example: {HEADERS_EXAMPLE}"
            )
    else:
        settings.HEADERS = None


@rstuf.group()  # type: ignore
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.option(
    "--headers",
    "-H",
    help=("Headers to include in the request. " f"Example: {HEADERS_EXAMPLE}"),
    required=False,
)
@click.pass_context
def admin(
    context: click.Context, api_server: Optional[str], headers: Optional[str]
):
    """Administrative Commands"""
    # Because of tests it has to be in a separate function.
    _set_settings(context, api_server, headers)  # pragma: no cover


@admin.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """
