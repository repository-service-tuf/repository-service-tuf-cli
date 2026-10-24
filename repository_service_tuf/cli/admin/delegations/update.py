# SPDX-FileCopyrightText: 2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from typing import Optional

import click
from rich.markdown import Markdown
from tuf.api.metadata import Targets

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin.delegations import delegations
from repository_service_tuf.cli.admin.helpers import (
    _configure_delegation_update,
    _get_latest_md,
)
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    send_payload,
    task_status,
)

DEFAULT_PATH = "delegations-update.json"


@delegations.command()  # type: ignore
@click.option(
    "--metadata-url",
    help="URL to the RSTUF API metadata storage.",
    type=str,
    required=True,
)
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
        "Run update in dry-run mode without sending result to API. "
        "Ignores options and configurations related to API."
    ),
)
@click.pass_context
def update(
    context: click.Context,
    metadata_url: str,
    out: Optional[click.File],
    dry_run: bool,
) -> None:
    """
    Perform an update of an existing Targets (delegation) metadata role.

    Changes the role's paths, threshold, expiration policy, or the keys it
    trusts -- switching it between the repository online key and offline
    keys, or replacing the offline keys it trusts.

    The role's current configuration is read from the repository's trusted
    Targets metadata at `--metadata-url`, so the update starts from what the
    repository trusts today rather than from scratch.

    * If `--out [FILENAME]` is passed, result is written to local FILENAME
    (in addition to being sent to the API).

    * If `--dry-run` is passed, result is not sent to the API.
    You can still pass `--out [FILENAME]` to store the result locally.
    """
    console.print("\n", Markdown("# Update Targets Metadata Tool"))
    settings = context.obj["settings"]

    # Make sure user understands that result will be send to the API and if the
    # the user wants something else should use '--dry-run'.
    if settings.get("SERVER") is None and not dry_run:
        raise click.ClickException(
            "Either '--api-sever' admin option/'SERVER' in RSTUF config or "
            "'--dry-run' needed"
        )

    targets = _get_latest_md(metadata_url, Targets.type)
    current = targets.signed.delegations
    if current is None:
        raise click.ClickException("Metadata has no delegations.")
    if current.succinct_roles:
        raise click.ClickException(
            "Metadata uses succinct roles, not allowed."
        )

    updated = _configure_delegation_update(current)
    payload = {"delegations": updated.to_dict()}

    if out:
        json.dump(
            payload,
            out,  # type: ignore
            indent=2,
        )
        console.print(f"Saved result to '{out.name}'")

    if settings.get("SERVER") and not dry_run:
        console.print(
            f"\nSending update Metadata delegation {settings.SERVER}"
        )
        task_id = send_payload(
            settings,
            URL.DELEGATIONS.value,
            payload,
            "Metadata delegation update accepted.",
            "Update Metadata finished.",
            method=Methods.PUT,
        )
        task_status(task_id, settings, "Update Metadata status:")
        console.print("\nMetadata delegation updated and sent to the API!\n")
