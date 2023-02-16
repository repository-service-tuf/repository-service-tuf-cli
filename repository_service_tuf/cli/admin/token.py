# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import click
from rich.console import Console  # type: ignore

from repository_service_tuf.cli.admin import admin
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    is_logged,
    request_server,
)

console = Console()


@admin.group()
@click.pass_context
def token(context):
    """
    Token Management.
    """


@token.command()
@click.option(
    "-e",
    "--expires",
    "expires",
    help="Expires in hours. Default: 24",
    default=24,
    required=False,
    show_default=True,
)
@click.option(
    "-s",
    "--scope",
    "scope",
    help=(
        "Scope to grant. Multiple is accepted. Ex: -s write:targets"
        " -s read:settings"
    ),
    multiple=True,
    required=True,
)
@click.pass_context
def generate(context, scope, expires):
    """
    Generate new token.
    """
    settings = context.obj.get("settings")
    server = settings.get("SERVER")
    logged_token = settings.get("TOKEN")
    login = is_logged(server, logged_token)
    if login.state is False:
        raise click.ClickException("Not logged. Use 'rstuf-cli admin login'")

    headers = {"Authorization": f"Bearer {logged_token}"}
    payload = {"scopes": list(scope), "expires": expires}
    response = request_server(
        server,
        f"{URL.token.value}new/",
        Methods.post,
        headers=headers,
        payload=payload,
    )

    if (
        response.status_code != 200
        or response.json().get("access_token") is None
    ):
        raise click.ClickException(
            f"Error: {response.status_code} {response.json()['detail']}"
        )

    console.print_json(response.text)


@token.command()
@click.argument("token")
@click.pass_context
def inspect(context, token):
    "Show token information details."

    settings = context.obj.get("settings")
    server = settings.get("SERVER")
    logged_token = settings.get("TOKEN")
    login = is_logged(server, logged_token)
    if login.state is False:
        raise click.ClickException("Not logged. Use 'rstuf-cli admin login'")

    headers = {"Authorization": f"Bearer {logged_token}"}
    response = request_server(
        server,
        f"{URL.token.value}?token={token}",
        Methods.get,
        headers=headers,
    )

    if response.status_code != 200 or response.json().get("data") is None:
        raise click.ClickException(
            f"Error: {response.status_code} {response.text}"
        )

    console.print_json(response.text)
