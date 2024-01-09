# SPDX-License-Identifier: MIT

from typing import Optional

from click import Context
from rich import print_json

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.artifact import artifact
from repository_service_tuf.helpers.api_client import URL, send_payload
from repository_service_tuf.helpers.cli import (
    create_artifact_add_payload_from_filepath,
)


@artifact.command()
@click.argument(
    "filepath",
    type=click.Path(exists=True),
    # Currently, this is required. If we support adding artifacts without
    # giving the filepath then we need to set it to `False` and implement our
    # own validation to check whether the argument is needed based on the
    # passed user options.
    required=True,
)
@click.option(
    "-p",
    "--path",
    help="A custom path (`TARGETPATH`) for the file, defined in the metadata.",
    type=str,
    required=False,
    default=None,
)
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.pass_context
def add(
    context: Context,
    filepath: str,
    path: Optional[str],
    api_server: Optional[str],
) -> None:
    """
    Add artifacts to the TUF metadata.

    A POST /api/v1/artifacts/ request to the RSTUF API service is carried out,
    where:
    - file info is discovered and added to the request payload. The blake2b-256
    cryptographic hash function is used to hash the file.
    - `custom` key of the payload is an empty object
    - `path` key of the payload is defined by the user
    """

    settings = context.obj.get("settings")
    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        raise click.ClickException(
            "Requires '--api-server' "
            "Example: --api-server https://api.rstuf.example.com"
        )

    payload = create_artifact_add_payload_from_filepath(
        filepath=filepath, path=path
    )

    task_id = send_payload(
        settings=settings,
        url=URL.ARTIFACTS.value,
        payload=payload,
        expected_msg="New Artifact(s) successfully submitted.",
        command_name="Artifact Addition",
    )

    console.print("Successfully submitted task with a payload of:")
    print_json(data=payload)
    console.print(f"\nRSTUF task ID (use to check its status) is: {task_id}")
