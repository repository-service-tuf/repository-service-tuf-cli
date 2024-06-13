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
    "sign_payload",
    type=click.File("r"),
    required=True,
)
@click.pass_context
def sign(context: click.Context, sign_payload: click.File):
    """Send sign payload to an existing RSTUF API deployment."""
    settings = context.obj["settings"]

    task_id = send_payload(
        settings=settings,
        url=URL.METADATA_SIGN.value,
        payload=json.load(sign_payload),  # type: ignore
        expected_msg="Metadata sign accepted.",
        command_name="Metadata sign",
    )
    task_status(task_id, settings, "Metadata sign status: ")
    console.print("\nMetadata Signed! 🔑\n")
