# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from enum import Enum
from typing import Any, Dict, Optional

import requests
import rich_click as click
from dynaconf import LazySettings
from requests.exceptions import ConnectionError
from rich.console import Console

console = Console()


class URL(Enum):
    BOOTSTRAP = "api/v1/bootstrap/"
    CONFIG = "api/v1/config/"
    METADATA = "api/v1/metadata/"
    TASK = "api/v1/task/?task_id="
    PUBLISH_ARTIFACTS = "api/v1/artifacts/publish/"
    METADATA_SIGN = "api/v1/metadata/sign/"
    METADATA_SIGN_DELETE = "api/v1/metadata/sign/delete"
    ARTIFACTS = "api/v1/artifacts/"
    ARTIFACTS_DELETE = "api/v1/artifacts/delete"
    DELEGATIONS = "api/v1/delegations/"
    DELEGATIONS_DELETE = "api/v1/delegations/delete"


class Methods(Enum):
    GET = "get"
    POST = "post"
    DELETE = "delete"


def request_server(
    server: str,
    url: str,
    method: Methods,
    payload: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    try:
        if method == Methods.GET:
            response = requests.get(
                f"{server}/{url}",
                json=payload,
                data=data,
                headers=headers,
                timeout=300,
            )

        elif method == Methods.POST:
            response = requests.post(
                f"{server}/{url}",
                json=payload,
                data=data,
                headers=headers,
                timeout=300,
            )

        elif method == Methods.DELETE:
            response = requests.delete(
                f"{server}/{url}",
                json=payload,
                data=data,
                headers=headers,
                timeout=300,
            )

        else:
            raise ValueError("Internal Error. Invalid HTTP/S Method.")

    except ConnectionError:
        raise click.ClickException(f"Failed to connect to {server}")

    return response


def bootstrap_status(settings: LazySettings) -> Dict[str, Any]:
    response = request_server(
        settings.SERVER,
        URL.BOOTSTRAP.value,
        Methods.GET,
        headers=settings.HEADERS,
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


def get_task(
    task_id: str,
    settings: LazySettings,
) -> tuple[Dict[str, Any], requests.Response]:

    state_response = request_server(
        settings.SERVER,
        f"{URL.TASK.value}{task_id}",
        Methods.GET,
        headers=settings.HEADERS,
    )

    if state_response.status_code != 200:
        raise click.ClickException(
            f"Unexpected response {state_response.text}"
        )

    data = state_response.json().get("data")

    if data is None:
        raise click.ClickException(f"No data received {state_response.text}")

    return data, state_response


def task_status(
    task_id: str,
    settings: LazySettings,
    title: Optional[str],
    silent: Optional[bool] = False,
) -> Dict[str, Any]:
    received_states = []
    while True:

        data, state_response = get_task(task_id, settings)

        if state := data.get("state"):
            if state not in received_states:
                if silent is False:
                    console.print(f"{title} {state}")
                received_states.append(state)
            else:
                if silent is False:
                    console.print(".", end="")

            if state == "SUCCESS":
                if result := data.get("result"):
                    if result.get("status") is True:
                        return data
                    else:
                        raise click.ClickException(
                            "Task status is not successful: "
                            f"{state_response.text}"
                        )
                else:
                    raise click.ClickException(
                        f"No result received in data {state_response.text}"
                    )

            elif state == "FAILURE":
                raise click.ClickException(f"Failed: {state_response.text}")
            elif state == "ERRORED":
                # If task.state is "ERRORED" it means there is an internal
                # RSTUF error and data contains error information.
                raise click.ClickException(
                    f"Errored: {data['result']['error']}"
                )

        else:
            raise click.ClickException(
                f"No state in data received {state_response.text}"
            )


def publish_artifacts(settings: LazySettings) -> str:
    publish_artifacts = request_server(
        settings.SERVER,
        URL.PUBLISH_ARTIFACTS.value,
        Methods.POST,
        headers=settings.HEADERS,
    )
    if publish_artifacts.status_code != 202:
        raise click.ClickException(
            f"Failed to publish artifacts. {publish_artifacts.status_code} "
            f"{publish_artifacts.text}"
        )
    task_id = publish_artifacts.json()["data"]["task_id"]

    return task_id


def send_payload(
    settings: LazySettings,
    url: str,
    payload: Dict[str, Any],
    expected_msg: str,
    command_name: str,
    expected_status_code: Optional[int] = 202,
) -> str:
    """
    Send 'payload' to a given 'settings.SERVER'.

    Args:
        settings: the command context settings object
        url: one of the URLs to a given endpoint as defined in api_client.py
        payload: dictionary containing the payload to send
        expected_msg: expected message to receive as a response to the request
        command_name: name of the command sending the payload, used for logging
        expected_status_code: [Optional] expected status code. Default: 202
    Returns:
        Task id of the job sending the payload.
    """
    response = request_server(
        settings.SERVER,
        url,
        Methods.POST,
        payload,
        headers=settings.HEADERS,
    )

    if response.status_code != expected_status_code:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )

    response_json = response.json()
    if (
        response_json.get("message") is None
        or response_json.get("message") != expected_msg
    ):
        raise click.ClickException(response.text)

    if data := response_json.get("data"):
        task_id = data.get("task_id")
        if task_id is None:
            raise click.ClickException(
                f"Failed to get `task id` {response.text}"
            )
        console.print(f"{command_name} status: ACCEPTED ({task_id})")

        return task_id
    else:
        raise click.ClickException(
            f"Failed to get task response data {response.text}"
        )
