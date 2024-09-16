# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from copy import deepcopy
from dataclasses import asdict
from typing import Optional

import click
from rich.markdown import Markdown
from rich.prompt import Confirm
from tuf.api.metadata import Metadata, Root

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin.helpers import (
    EXPIRY_FORMAT,
    Metadatas,
    UpdatePayload,
    _add_root_signatures_prompt,
    _configure_online_key_prompt,
    _configure_root_keys_prompt,
    _expiry_prompt,
    _get_latest_md,
    _print_root,
    _threshold_prompt,
)
from repository_service_tuf.cli.admin.metadata import metadata
from repository_service_tuf.helpers.api_client import (
    URL,
    send_payload,
    task_status,
)

DEFAULT_PATH = "update-payload.json"


@metadata.command()  # type: ignore
@click.option(
    "--in",
    "input",
    help="Input file containing current trusted root JSON.",
    type=click.File("rb"),
    required=False,
)
@click.option(
    "--metadata-url",
    help="URL to the RSTUF API metadata storage.",
    type=str,
    required=False,
)
@click.option(
    "--out",
    is_flag=False,
    flag_value=DEFAULT_PATH,
    help=f"Write json result to FILENAME (default: '{DEFAULT_PATH}')",
    type=click.File("w"),
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Run update in dry-run mode without sending result to API.",
)
@click.pass_context
def update(
    context: click.Context,
    input: Optional[click.File],
    metadata_url: Optional[str],
    out: Optional[click.File],
    dry_run: bool,
) -> None:
    """
    Perform metadata update and send result to API.

    * If `--metadata-url TEXT` is passed, the latest root will be fetched from
    metadata storage.

    * If `--in FILENAME` is passed, input is not read from API but from local
    FILENAME.

    * If both `--metadata-url TEXT` and `--in FILENAME` are passed, then
    `--metadata-url TEXT` will have higher priority.

    * If `--out [FILENAME]` is passed, result is written to local FILENAME
    (in addition to being sent to API).

    * If `--dry-run` is passed, result is not sent to API.
    You can still pass `--out [FILENAME]` to store the result locally.

    * If `--in` and `--dry-run` are passed, `--api-server` admin option and
    `SERVER` from config will be ignored.
    """
    console.print("\n", Markdown("# Metadata Update Tool"))
    if not input and not metadata_url:
        raise click.ClickException("Either '--in' or '--metadata-url' needed")

    settings = context.obj["settings"]
    # Make sure user understands that result will be send to the API and if the
    # the user wants something else should use '--dry-run'.
    if not settings.get("SERVER") and not dry_run:
        raise click.ClickException(
            "Either '--api-server' admin option/'SERVER' in RSTUF config or "
            "'--dry-run' needed"
        )

    ###########################################################################
    # Load root
    prev_root_md: Metadata[Root]
    if metadata_url:
        prev_root_md = _get_latest_md(metadata_url, Root.type)
        console.print(
            f"Latest root version found: {prev_root_md.signed.version}"
        )
    else:
        prev_root_md = Metadata.from_bytes(input.read())  # type: ignore

    root = deepcopy(prev_root_md.signed)

    ###########################################################################
    # Configure root expiration
    console.print(Markdown("## Root Expiration"))

    expired = root.is_expired()
    expiry_str = (
        f"Root expire{'d' if expired else 's'} "
        f"on {root.expires:{EXPIRY_FORMAT}}."
    )
    if expired or Confirm.ask(
        f"{expiry_str} Do you want to change the expiry date?", default=True
    ):
        _, date = _expiry_prompt("root")
        root.expires = date

    ###########################################################################
    # Configure root keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)

    threshold_str = f"Root signature threshold is {root_role.threshold}."
    if Confirm.ask(
        f"{threshold_str} Do you want to change the threshold?", default=False
    ):
        root_role.threshold = _threshold_prompt("root")

    _configure_root_keys_prompt(root)

    ###########################################################################
    # Configure Online Key
    console.print(Markdown("## Online Key"))
    _configure_online_key_prompt(root)

    ###########################################################################
    # Bump version
    # TODO: check if metadata changed, or else abort? start over?
    root.version += 1

    ###########################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    root_md = Metadata(root)
    _print_root(root)
    # TODO: ask to continue? or abort? or start over?

    ###########################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))
    _add_root_signatures_prompt(root_md, prev_root_md.signed)

    ###########################################################################
    # Send payload to the API and/or save it locally

    payload = UpdatePayload(Metadatas(root_md.to_dict()))
    if out:
        json.dump(asdict(payload), out, indent=2)  # type: ignore
        console.print(f"Saved result to '{out.name}'")

    if settings.get("SERVER") and not dry_run:
        task_id = send_payload(
            settings=settings,
            url=URL.METADATA.value,
            payload=asdict(payload),
            expected_msg="Metadata update accepted.",
            command_name="Metadata Update",
        )
        task_status(task_id, settings, "Metadata Update status: ")

        console.print("Root metadata update completed. 🔐 🎉")
