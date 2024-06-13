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
    "metadata_update_payload",
    type=click.File("r"),
    required=True,
)
@click.pass_context
def update(context: click.Context, metadata_update_payload: click.File):
    """Send metadata update payload to an existing RSTUF API deployment."""
    settings = context.obj["settings"]

    task_id = send_payload(
        settings=settings,
        url=URL.METADATA.value,
        payload=json.load(metadata_update_payload),  # type: ignore
        expected_msg="Metadata update accepted.",
        command_name="Metadata Update",
    )
    task_status(task_id, settings, "Metadata Update status: ")
    console.print("Root metadata update completed. 🔐 🎉")
