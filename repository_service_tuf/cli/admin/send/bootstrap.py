# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors

# SPDX-License-Identifier: MIT

import json

from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin.send import click, send
from repository_service_tuf.helpers.api_client import (
    URL,
    send_payload,
    task_status,
)


@send.command()  # type: ignore
@click.argument(
    "bootstrap_payload",
    type=click.File("r"),
    required=True,
)
@click.pass_context
def bootstrap(context: click.Context, bootstrap_payload: click.File):
    """Send payload and bootstrap to an existing RSTUF API deployment."""
    settings = context.obj["settings"]

    task_id = send_payload(
        settings=settings,
        url=URL.BOOTSTRAP.value,
        payload=json.load(bootstrap_payload),  # type: ignore
        expected_msg="Bootstrap accepted.",
        command_name="Bootstrap",
    )
    task_status(task_id, settings, "Bootstrap status: ")
    console.print("\nBootstrap completed. 🔐 🎉")
