# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

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
    bootstrap_status,
    send_payload,
    task_status,
)
from repository_service_tuf.helpers.tuf import save_payload

DEFAULT_PATH = "ceremony-payload.json"


@admin.command()  # type: ignore
@click.argument(
    "output",
    required=False,
    type=click.File("w"),
)
@click.pass_context
def ceremony(context: Any, output: Optional[click.File]) -> None:
    """Bootstrap Ceremony to create initial root metadata and RSTUF config."""
    console.print("\n", Markdown("# Metadata Bootstrap Tool"))
    settings = context.obj["settings"]
    # Running online ceremony requires connection to the server and
    # confirmation that the server is indeed ready for bootstap.
    if not settings.get("SERVER") and not output:
        raise click.ClickException(
            "Either '--api-sever'/'SERVER' in RSTUF config or 'OUTPUT' needed"
        )

    if settings.get("SERVER"):
        bs_status = bootstrap_status(settings)
        if bs_status.get("data", {}).get("bootstrap") is True:
            raise click.ClickException(f"{bs_status.get('message')}")

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
    if output:
        path = output.name if output is not None else DEFAULT_PATH
        save_payload(path, asdict(bootstrap_payload))
        console.print(f"Saved result to '{path}'")

    if settings.get("SERVER"):
        task_id = send_payload(
            settings=settings,
            url=URL.BOOTSTRAP.value,
            payload=asdict(bootstrap_payload),
            expected_msg="Bootstrap accepted.",
            command_name="Bootstrap",
        )
        task_status(task_id, settings, "Bootstrap status: ")
        console.print("\nCeremony done. 🔐 🎉. Bootstrap completed.")
