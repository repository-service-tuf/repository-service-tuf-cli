# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from dataclasses import asdict
from typing import Any, Optional

import click
from rich.markdown import Markdown

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
    Metadata,
    Metadatas,
    Role,
    Roles,
    Root,
    Settings,
    _add_root_signatures_prompt,
    _configure_delegations_prompt,
    _configure_online_key_prompt,
    _configure_root_keys_prompt,
    _expiry_prompt,
    _print_root,
    _settings_prompt,
    _threshold_prompt,
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
@click.option(
    "-t",
    "--timeout",
    default=300,
    help="Timeout in seconds",
)
@click.pass_context
def ceremony(
    context: Any, out: Optional[click.File], dry_run: bool, timeout: int
) -> None:
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
    bs_settings = _settings_prompt()
    _configure_delegations_prompt(bs_settings)

    console.print(Markdown("##  Root expiry"))
    root_days, root_date = _expiry_prompt("root")
    root.expires = root_date

    # Using BINS or Custom Delegations
    if bs_settings.delegations:
        delegations = bs_settings.delegations
        bins = None
    else:
        delegations = None
        if bs_settings.bins_expiry and bs_settings.bins_number:
            bins = BinsRole(bs_settings.bins_expiry, bs_settings.bins_number)

    roles = Roles(
        Role(root_days),
        Role(bs_settings.timestamp_expiry),
        Role(bs_settings.snapshot_expiry),
        Role(bs_settings.targets_expiry),
        bins,
        delegations.to_dict() if delegations else None,
    )

    ###########################################################################
    # Configure Root Keys
    console.print(Markdown("## Root Keys"))
    root_role = root.get_delegated_role(Root.type)
    root_role.threshold = _threshold_prompt("root")
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
    bootstrap_settings = Settings(roles)
    bootstrap_payload = CeremonyPayload(bootstrap_settings, metadatas, timeout)
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
