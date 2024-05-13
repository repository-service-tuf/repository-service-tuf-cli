# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from copy import deepcopy
from dataclasses import asdict

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
from repository_service_tuf.cli.admin import metadata
from repository_service_tuf.cli.admin.helpers import (
    EXPIRY_FORMAT,
    Metadatas,
    UpdatePayload,
    _add_root_signatures_prompt,
    _configure_online_key_prompt,
    _configure_root_keys_prompt,
    _expiry_prompt,
    _print_root,
    _root_threshold_prompt,
    _warn_no_save,
)


@metadata.command()  # type: ignore
@click.argument("root_in", type=click.File("rb"))
@click.option(
    "--save",
    "-s",
    is_flag=False,
    flag_value="update-payload.json",
    help="Write json result to FILENAME (default: 'update-payload.json')",
    type=click.File("w"),
)
def update(root_in, save) -> None:
    """Update root metadata and bump version."""
    console.print("\n", Markdown("# Metadata Update Tool"))

    if not save:
        _warn_no_save()

    ###########################################################################
    # Load root
    # TODO: load from API
    prev_root_md = Metadata[Root].from_bytes(root_in.read())
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
        root_role.threshold = _root_threshold_prompt()

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
    # Dump payload
    # TODO: post to API
    payload = UpdatePayload(Metadatas(root_md.to_dict()))
    if save:
        json.dump(asdict(payload), save, indent=2)
        console.print(f"Saved result to '{save.name}'")
