# SPDX-License-Identifier: MIT

from typing import Any, Dict

from click import Context

from repository_service_tuf.cli import click
from repository_service_tuf.cli.task import task
from repository_service_tuf.helpers.api_client import task_status


@task.command()
@click.argument(
    "task_id",
    type=str,
    required=True,
)
@click.option(
    "--api-server",
    help="RSTUF API URL, i.e., http://127.0.0.1",
    required=False,
)
@click.pass_context
def info(context: Context, task_id: str, api_server: str) -> Dict[str, Any]:
    """
    Retrieve task state.

    A GET /api/v1/task/ request to the RSTUF API service is carried out.
    """

    settings = context.obj.get("settings")

    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        raise click.ClickException(
            "Requires '--api-server' or configuring the `.rstuf.yml` file. "
            "Example: --api-server https://api.rstuf.example.com"
        )

    status = task_status(
        task_id=task_id, settings=settings, title="Task status:"
    )

    return status
