# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from typing import Dict

from dynaconf import loaders
from rich import markdown, prompt  # type: ignore
from rich.console import Console  # type: ignore

from repository_service_tuf.cli import click
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    is_logged,
    request_server,
)

console = Console()


def _login(server: str, data: Dict[str, str]):

    token_response = request_server(
        server, URL.token.value, Methods.post, data=data
    )
    if token_response.status_code != 200:
        raise click.ClickException(token_response.json()["detail"])

    return token_response.json()


def _run_login(context, server_, user_, password_, expires_):
    settings = context.obj.get("settings")
    console.print(
        markdown.Markdown(
            f"""# Login to Repository Service for TUF\n
            The server and token will generate a token and it will be
            stored in {context.obj.get('config')}
            """
        ),
        width=100,
    )
    while True:
        if server_ is None:
            server = prompt.Prompt.ask(
                "\nServer Address",
                default=settings.get("SERVER"),
                show_default=True,
            )
        else:
            server = server_
        if server.startswith("http") is False:
            console.print(
                f"Please use 'http://{server}' or 'https://{server}'"
            )
            server_ = None
        else:
            break

    if user_ is None:
        username = prompt.Prompt.ask(
            "Username", default="admin", show_default=True
        )
    else:
        username = user_

    if password_ is None:
        password = click.prompt("Password", hide_input=True)
    else:
        password = password_

    if expires_ is None:
        expires = prompt.IntPrompt.ask(
            "Expire (in hours)", default=24, show_default=False
        )
    else:
        expires = expires_

    data = {
        "username": username,
        "password": password,
        "scope": (
            "write:targets "
            "write:bootstrap "
            "read:bootstrap "
            "read:settings "
            "read:token "
            "read:tasks "
            "write:token "
        ),
        "expires": expires,
    }

    token = _login(server, data)
    settings.SERVER = server
    settings.TOKEN = token["access_token"]
    loaders.write(context.obj.get("config"), settings.to_dict())

    console.print(f"Token stored in {context.obj.get('config')}\n")
    console.print("Login successful.")


@admin.command()
@click.option(
    "-f", "--force", "force", help="Force login/Renew token", is_flag=True
)
@click.option("-s", "server_", help="Server", required=False, default=None)
@click.option("-u", "user_", help="User", required=False, default=None)
@click.option("-p", "password_", help="Password", required=False, default=None)
@click.option(
    "-e", "expires_", help="Expires in Hours", required=False, default=None
)
@click.pass_context
def login(context, force, server_, user_, password_, expires_):
    """
    Login to Repository Service for TUF (API).
    """
    settings = context.obj.get("settings")
    server = settings.get("SERVER")
    token = settings.get("TOKEN")

    if force is False and server is not None and token is not None:
        response = is_logged(server, token)
        if response.state is False:
            _run_login(context, server_, user_, password_, expires_)

        else:
            data = response.data
            if response.data.get("expired") is False:
                console.print(
                    f"Already logged to {server}. "
                    f"Valid until '{data['expiration']}'"
                )

    else:
        _run_login(context, server_, user_, password_, expires_)
