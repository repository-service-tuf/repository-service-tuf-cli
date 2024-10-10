# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from typing import Optional

import click
from rich.markdown import Markdown

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin.delegations import delegations
from repository_service_tuf.cli.admin.helpers import _configure_delegations
from repository_service_tuf.helpers.api_client import (
    URL,
    send_payload,
    task_status,
)

DEFAULT_PATH = "delegations-new.json"


@delegations.command()  # type: ignore
@click.option(
    "--out",
    is_flag=False,
    flag_value=DEFAULT_PATH,
    help=f"Write output JSON result to FILENAME (default: '{DEFAULT_PATH}')",
    type=click.File("w"),
    required=False,
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help=(
        "Run sign in dry-run mode without sending result to API. "
        "Ignores options and configurations related to API."
    ),
)
@click.pass_context
def new(
    context: click.Context,
    out: Optional[click.File],
    dry_run: bool,
) -> None:
    """
    Perform creation of new Targets (delegation) metadata.

    * If `--out [FILENAME]` is passed, result is written to local FILENAME
    (in addition to being sent to API).

    * If `--dry-run` is passed, result is not sent to API.
    You can still pass `--out [FILENAME]` to store the result locally.
    """
    console.print("\n", Markdown("# New Targets Metadata Tool"))
    settings = context.obj["settings"]

    # Make sure user understands that result will be send to the API and if the
    # the user wants something else should use '--dry-run'.
    if settings.get("SERVER") is None and not dry_run:
        raise click.ClickException(
            "Either '--api-sever' admin option/'SERVER' in RSTUF config or "
            "'--dry-run' needed"
        )

    delegations = _configure_delegations()

    if out:
        json.dump(
            {"delegations": delegations.to_dict()},
            out,  # type: ignore
            indent=2,
        )
        console.print(f"Saved result to '{out.name}'")

    if settings.get("SERVER") and not dry_run:
        console.print(f"\nSending new Metadata delegation {settings.SERVER}")
        task_id = send_payload(
            settings,
            URL.DELEGATIONS.value,
            {"delegations": delegations.to_dict()},
            "New Metadata accepted.",
            "New Metadata finished.",
        )
        task_status(task_id, settings, "New Metadata status:")
        console.print("\nNew Metadata created and sent to the API!\n")
