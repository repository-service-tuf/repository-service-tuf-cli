# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

import requests
from dynaconf import LazySettings
from requests.exceptions import ConnectionError
from rich.console import Console

from repository_service_tuf.cli import click

console = Console()


class URL(Enum):
    token = "api/v1/token/"  # nosec bandit: not hard coded password.
    bootstrap = "api/v1/bootstrap/"
    task = "api/v1/task/?task_id="
    publish_targets = "api/v1/targets/publish/"


class Methods(Enum):
    get = "get"
    post = "post"


@dataclass
class Login:
    state: bool
    data: Optional[Dict[str, Any]] = None


def request_server(
    server: str,
    url: str,
    method: Methods,
    payload: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    try:
        if method == Methods.get:
            response = requests.get(
                f"{server}/{url}", json=payload, data=data, headers=headers
            )

        elif method == Methods.post:
            response = requests.post(
                f"{server}/{url}", json=payload, data=data, headers=headers
            )

        else:
            raise ValueError("Internal Error. Invalid HTTP/S Method.")

    except ConnectionError:
        raise click.ClickException(f"Failed to connect to {server}")

    return response


def is_logged(server: str, token: str):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{URL.token.value}?token={token}"
    response = request_server(server, url, Methods.get, headers=headers)
    if response.status_code == 401 or response.status_code == 403:
        return Login(state=False)

    elif response.status_code == 200:
        data = response.json().get("data", {})
        if data.get("expired") is False:
            return Login(state=True, data=data)

    else:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )


def get_headers(settings: LazySettings) -> Dict[str, str]:
    server = settings.get("SERVER")
    token = settings.get("TOKEN")
    if server and token:
        token_access_check = is_logged(server, token)
        if token_access_check.state is False:
            raise click.ClickException(
                f"{str(token_access_check.data)}"
                "\n\nTry re-login: 'rstuf admin login'"
            )

        expired_admin = token_access_check.data.get("expired")
        if expired_admin is True:
            raise click.ClickException(
                "The token has expired. Run 'rstuf admin login'"
            )
        else:
            headers = {"Authorization": f"Bearer {token}"}
            response = request_server(
                server, URL.bootstrap.value, Methods.get, headers=headers
            )
            if response.status_code != 200:
                raise click.ClickException(
                    f"Unexpected error: {response.text}"
                )
    else:
        raise click.ClickException("Login first. Run 'rstuf admin login'")

    return headers


def bootstrap_status(settings: LazySettings) -> Dict[str, Any]:
    headers = get_headers(settings)
    response = request_server(
        settings.SERVER, URL.bootstrap.value, Methods.get, headers=headers
    )
    if response.status_code == 404:
        raise click.ClickException(
            f"Server {settings.SERVER} does not allow bootstrap"
        )
    if response.status_code != 200:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )

    bootstrap_json = response.json()
    if bootstrap_json is None:
        raise click.ClickException(f"Unexpected error {response.text}")

    return bootstrap_json


def task_status(
    task_id: str, settings: LazySettings, title: Optional[str]
) -> Dict[str, Any]:
    headers = get_headers(settings)
    received_states = []
    while True:
        state_response = request_server(
            settings.SERVER,
            f"{URL.task.value}{task_id}",
            Methods.get,
            headers=headers,
        )

        if state_response.status_code != 200:
            raise click.ClickException(
                f"Unexpected response {state_response.text}"
            )

        data = state_response.json().get("data")

        if data:
            if state := data.get("state"):
                if state not in received_states:
                    console.print(f"{title}{state}")
                    received_states.append(state)
                else:
                    console.print(".", end="")

                if state == "SUCCESS":
                    return data

                elif state == "FAILURE":
                    raise click.ClickException(
                        f"Failed: {state_response.text}"
                    )

            else:
                raise click.ClickException(
                    f"No state in data received {state_response.text}"
                )
        else:
            raise click.ClickException(
                f"No data received {state_response.text}"
            )
        time.sleep(2)


def publish_targets(settings: LazySettings) -> str:
    headers = get_headers(settings)
    publish_targets = request_server(
        settings.SERVER,
        URL.publish_targets.value,
        Methods.post,
        headers=headers,
    )
    if publish_targets.status_code != 202:
        raise click.ClickException(
            f"Failed to publish targets. {publish_targets.status_code} "
            f"{publish_targets.text}"
        )
    task_id = publish_targets.json()["data"]["task_id"]

    return task_id
