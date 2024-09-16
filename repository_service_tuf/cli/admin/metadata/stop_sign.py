# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import copy
from typing import Union

import click
from rich import prompt
from rich.markdown import Markdown

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin.helpers import (
    Metadata,
    Root,
    Targets,
    _get_pending_roles,
    _print_root,
    _print_targets,
    _select_role,
)
from repository_service_tuf.cli.admin.metadata import metadata
from repository_service_tuf.helpers.api_client import (
    URL,
    send_payload,
    task_status,
)


@metadata.command()  # type: ignore
@click.pass_context
def stop_sign(context: click.Context) -> None:
    """Stop an existing pending signing event for a given metadata role."""
    console.print("\n", Markdown("# Stop Metadata Signing Tool"))
    settings = context.obj["settings"]
    # Make sure there is a way to get a DAS metadata for signing.
    if not settings.get("SERVER"):
        raise click.ClickException(
            "Needed '--api-server' admin option or 'SERVER' in RSTUF cofig"
        )

    pending_roles = _get_pending_roles(settings)
    while True:
        console.print("\nSelect which metadata signing process to stop:")
        role = _select_role(pending_roles)
        md: Metadata[Union[Root, Targets]] = Metadata.from_dict(
            copy.deepcopy(pending_roles[role])
        )
        if md.signed.type == Root.type:
            _print_root(md.signed)
        elif md.signed.type == Targets.type:
            _print_targets(md.signed)

        confirmation = prompt.Confirm.ask(
            f"\nDo you still want to stop signing process for {role}?"
        )
        if confirmation:
            break

    task_id = send_payload(
        settings=settings,
        url=URL.METADATA_SIGN_DELETE.value,
        payload={"role": role},
        expected_msg="Metadata sign delete accepted.",
        command_name="Metadata delete sign",
    )
    task_status(task_id, settings, "Stop Signing process status: ")
    console.print(f"\nSigning process for {role} deleted!\n")
