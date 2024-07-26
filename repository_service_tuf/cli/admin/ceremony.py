# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from dataclasses import asdict
from typing import Any, Optional

import click
from rich.markdown import Markdown
from tuf.api.metadata import Metadata, Root

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.cli.admin.helpers import (
    BinsRole,
    CeremonyPayload,
    Metadatas,
    Role,
    Roles,
    Settings,
    _add_root_signatures_prompt,
    _configure_online_key_prompt,
    _configure_root_keys_prompt,
    _expiry_prompt,
    _online_settings_prompt,
    _print_root,
    _root_threshold_prompt,
)
from repository_service_tuf.helpers.api_client import (
    URL,
    send_payload,
    task_status,
)

DEFAULT_PATH = "ceremony-payload.json"


@admin.command()  # type: ignore
@click.option(
    "--out",
    is_flag=False,
    flag_value=DEFAULT_PATH,
    help=f"Write output json result to FILENAME (default: '{DEFAULT_PATH}')",
    type=click.File("w"),
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Run ceremony in dry-run mode without sending result to API.",
)
@click.pass_context
def ceremony(context: Any, out: Optional[click.File], dry_run: bool) -> None:
    """
    Perform ceremony and send result to API to trigger bootstrap.

    \b
    * If `--out [FILENAME]` is passed, result is written to local FILENAME
    (in addition to being sent to API).

    \b
    * If `--dry-run` is passed, result is not sent to API.
    You can still pass `--out [FILENAME]` to store the result locally.
    The `--api-server` admin option and `SERVER` from config will be ignored.
    """
    console.print("\n", Markdown("# Metadata Bootstrap Tool"))
    settings = context.obj["settings"]
    # Running online ceremony requires connection to the server and
    # confirmation that the server is indeed ready for bootstap.
    if not settings.get("SERVER") and not dry_run:
        raise click.ClickException(
            "Either '--api-server' admin option/'SERVER' in RSTUF config or "
            "'--dry-run' needed"
        )

    # Performs ceremony steps.
    root = Root()
    ###########################################################################
    # Configure online role settings
    console.print(Markdown("##  Online role settings"))
    online = _online_settings_prompt()

    console.print(Markdown("##  Root expiry"))
    root_days, root_date = _expiry_prompt("root")
    root.expires = root_date

    roles = Roles(
        Role(root_days),
        Role(online.timestamp_expiry),
        Role(online.snapshot_expiry),
        Role(online.targets_expiry),
        BinsRole(online.bins_expiry, online.bins_number),
    )

    ###########################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)
    root_role.threshold = _root_threshold_prompt()
    _configure_root_keys_prompt(root)

    ###########################################################################
    # Configure Online Key
    console.print(Markdown("## Online Key"))
    _configure_online_key_prompt(root)

    ###########################################################################
    # Review Metadata
    console.print(Markdown("## Review"))
    _print_root(root)
    # TODO: ask to continue? or abort? or start over?

    ###########################################################################
    # Sign Metadata
    console.print(Markdown("## Sign"))
    root_md = Metadata(root)
    _add_root_signatures_prompt(root_md, None)

    ###########################################################################
    metadatas = Metadatas(root_md.to_dict())
    roles_settings = Settings(roles)
    bootstrap_payload = CeremonyPayload(roles_settings, metadatas)
    # Dump payload when the user explicitly wants or doesn't send it to the API
    if out:
        json.dump(asdict(bootstrap_payload), out, indent=2)  # type: ignore
        console.print(f"Saved result to '{out.name}'")

    if settings.get("SERVER") and not dry_run:
        task_id = send_payload(
            settings=settings,
            url=URL.BOOTSTRAP.value,
            payload=asdict(bootstrap_payload),
            expected_msg="Bootstrap accepted.",
            command_name="Bootstrap",
        )
        task_status(task_id, settings, "Bootstrap status: ")
        console.print("\nCeremony done. 🔐 🎉. Bootstrap completed.")
