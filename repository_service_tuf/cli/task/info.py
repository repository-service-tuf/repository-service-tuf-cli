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
@click.pass_context
def info(context: Context, task_id: str) -> Dict[str, Any]:
    """
    Retrieve task state.

    A GET /api/v1/task/ request to the RSTUF API service is carried out.
    """

    settings = context.obj.get("settings")

    status = task_status(
        task_id=task_id, settings=settings, title="Task status:"
    )

    return status
