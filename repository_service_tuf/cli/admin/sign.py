# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from dataclasses import asdict

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
from repository_service_tuf.cli.admin import metadata
from repository_service_tuf.cli.admin.helpers import (
    SignPayload,
    _add_signature_prompt,
    _choose_signing_key_prompt,
    _filter_root_verification_results,
    _print_keys_for_signing,
    _print_root,
    _warn_no_save,
)


@metadata.command()  # type: ignore
@click.argument("root_in", type=click.File("rb"))
@click.argument("prev_root_in", type=click.File("rb"), required=False)
@click.option(
    "--save",
    "-s",
    is_flag=False,
    flag_value="sign-payload.json",
    help="Write json result to FILENAME (default: 'sign-payload.json')",
    type=click.File("w"),
)
def sign(root_in, prev_root_in, save) -> None:
    """Add one signature to root metadata."""
    console.print("\n", Markdown("# Metadata Signing Tool"))

    if not save:
        _warn_no_save()

    ###########################################################################
    # Load roots
    # TODO: load from API
    root_md = Metadata[Root].from_bytes(root_in.read())

    if prev_root_in:
        prev_root = Metadata[Root].from_bytes(prev_root_in.read()).signed

    else:
        prev_root = None
        version = root_md.signed.version
        if version > 1:
            raise click.ClickException(
                f"Previous root v{version-1} needed "
                f"to sign root v{version}."
            )

    ###########################################################################
    # Verify signatures
    root_result = root_md.signed.get_root_verification_result(
        prev_root,
        root_md.signed_bytes,
        root_md.signatures,
    )
    if root_result.verified:
        raise click.ClickException("Metadata already fully signed.")

    ###########################################################################
    # Review metadata
    console.print(Markdown("## Review"))
    _print_root(root_md.signed)

    ###########################################################################
    # Sign metadata
    console.print(Markdown("## Sign"))
    results = _filter_root_verification_results(root_result)
    keys = _print_keys_for_signing(results)
    key_idx = _choose_signing_key_prompt(len(keys), allow_skip=False)
    key = keys[key_idx - 1]
    signature = _add_signature_prompt(root_md, key)

    ###########################################################################
    # Dump payload
    # TODO: post to API
    if save:
        payload = SignPayload(signature=signature.to_dict())
        json.dump(asdict(payload), save, indent=2)
        console.print(f"Saved result to '{save.name}'")
