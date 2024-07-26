# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors

# SPDX-License-Identifier: MIT

from repository_service_tuf.cli.admin import admin, click


def _validate_settings(context: click.Context):
    settings = context.obj["settings"]
    if not settings.get("SERVER"):
        raise click.ClickException(
            "Needed '--api-server' admin option or 'SERVER' in RSTUF cofig"
        )


@admin.group()  # type: ignore
@click.pass_context
def send(context: click.Context):
    """Send a payload to an existing RSTUF API deployment"""
    _validate_settings(context)  # pragma: no cover
