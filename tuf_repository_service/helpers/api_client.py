from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

import requests

from tuf_repository_service.cli import click


class URL(Enum):
    token = "api/v1/token/"
    bootstrap = "api/v1/bootstrap/"
    task = "api/v1/task/?task_id="


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

    except requests.exceptions.ConnectionError:
        raise click.ClickException(f"Failed to connect to {server}")

    return response


def is_logged(server: str, token: str):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{URL.token.value}?token={token}"
    response = request_server(server, url, Methods.get, headers=headers)
    if response.status_code == 401 or response.status_code == 403:
        return Login(state=False)

    elif response.status_code == 200:
        data = response.json().get("data")
        if data.get("expired") is False:
            return Login(state=True, data=data)

    else:
        click.ClickException(
            f"Error {response.status_code} {response.json()['detail']}"
        )
