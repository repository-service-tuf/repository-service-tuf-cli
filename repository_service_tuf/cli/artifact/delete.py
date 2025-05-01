# SPDX-License-Identifier: MIT

from typing import Optional

from click import Context
from rich import print_json

from repository_service_tuf.cli import (
    HEADERS_EXAMPLE,
    _set_settings,
    click,
    console,
)
from repository_service_tuf.cli.artifact import artifact
from repository_service_tuf.helpers.api_client import URL, send_payload
from repository_service_tuf.helpers.cli import (
    create_artifact_delete_payload_from_filepath,
)


@artifact.command()
@click.argument(
    "path",
    required=True,
)
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.option(
    "--headers",
    "-H",
    help=("Headers to include in the request. " f"Example: {HEADERS_EXAMPLE}"),
    required=False,
)
@click.pass_context
def delete(
    context: Context,
    path: str,
    headers: Optional[str],
    api_server: Optional[str],
) -> None:
    """
    Delete artifacts to the TUF metadata.

    A POST /api/v1/artifacts/delete request to the RSTUF API service
    is carried out, where:

    - `PATH` is artifact path to be deleted as stored in the TUF metadata.
    """

    settings = _set_settings(context, api_server, headers)

    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        raise click.ClickException(
            "Requires '--api-server' "
            "Example: --api-server https://api.rstuf.example.com"
        )

    payload = create_artifact_delete_payload_from_filepath(path=path)

    task_id = send_payload(
        settings=settings,
        url=URL.ARTIFACTS_DELETE.value,
        payload=payload,
        expected_msg="Remove Artifact(s) successfully submitted.",
        command_name="Artifact Deletion",
    )

    console.print("Successfully submitted task with a payload of:")
    print_json(data=payload)
    console.print(f"\nRSTUF task ID (use to check its status) is: {task_id}")
