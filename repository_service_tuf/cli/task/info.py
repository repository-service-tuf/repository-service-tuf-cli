# SPDX-License-Identifier: MIT

from typing import Any, Dict

from click import Context
from rich import print_json

from repository_service_tuf.cli import HEADERS_EXAMPLE, _set_settings, click
from repository_service_tuf.cli.task import task
from repository_service_tuf.helpers.api_client import get_task, task_status


@task.command()
@click.argument(
    "task_id",
    type=str,
    required=True,
)
@click.option(
    "--all",
    "-a",
    help="Show all task details.",
    is_flag=True,
    required=False,
    default=False,
)
@click.option(
    "--api-server",
    help="RSTUF API URL, i.e., http://127.0.0.1",
    required=False,
)
@click.option(
    "--headers",
    "-H",
    help=("Headers to include in the request. " f"Example: {HEADERS_EXAMPLE}"),
    required=False,
)
@click.pass_context
def info(
    context: Context, task_id: str, api_server: str, headers: str, all: bool
) -> Dict[str, Any]:
    """
    Retrieve task state.

    A GET /api/v1/task/ request to the RSTUF API service is carried out.
    """

    settings = _set_settings(context, api_server, headers)

    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        raise click.ClickException(
            "Requires '--api-server' or configuring the `.rstuf.yml` file. "
            "Example: --api-server https://api.rstuf.example.com"
        )

    if all:
        data, _ = get_task(task_id=task_id, settings=settings)

        print_json(data=data)

    status = task_status(
        task_id=task_id, settings=settings, title="Task status:"
    )

    return status
