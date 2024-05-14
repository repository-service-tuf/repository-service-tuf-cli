# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from dataclasses import asdict
from typing import Any, Dict, Optional

import click
from rich.markdown import Markdown
from rich.prompt import Prompt
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
)
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    request_server,
    send_payload,
    task_status,
)


def _get_pending_roles(
    settings: Any, api_server: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        api_server = Prompt.ask("\n[cyan]API[/] URL address")
        settings.SERVER = api_server

    response = request_server(
        settings.SERVER, URL.METADATA_SIGN.value, Methods.GET
    )
    if response.status_code != 200:
        raise click.ClickException(
            f"Failed to retrieve metadata for signing. Error: {response.text}"
        )

    response_data: Dict[str, Any] = response.json().get("data")
    if response_data is None:
        raise click.ClickException(response.text)

    pending_roles: Dict[str, Dict[str, Any]] = response_data.get(
        "metadata", {}
    )
    if len(pending_roles) == 0:
        raise click.ClickException("No metadata available for signing")

    return pending_roles


@metadata.command()  # type: ignore
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.option(
    "--save",
    "-s",
    is_flag=False,
    flag_value="sign-payload.json",
    help="Write json result to FILENAME (default: 'sign-payload.json')",
    type=click.File("w"),
)
@click.pass_context
def sign(
    context: Any, api_server: Optional[str], save: Optional[click.File]
) -> None:
    """Add one signature to root metadata."""
    console.print("\n", Markdown("# Metadata Signing Tool"))
    ###########################################################################
    # Load roots
    settings = context.obj["settings"]
    pending_roles = _get_pending_roles(settings, api_server)
    root_md = Metadata[Root].from_dict(pending_roles[Root.type])

    if pending_roles.get(f"trusted_{Root.type}"):
        trusted_role = f"trusted_{Root.type}"
        prev_root = Metadata[Root].from_dict(pending_roles[trusted_role])

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
        prev_root.signed if prev_root is not None else None,
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
    # Send payload to the API and save it locally
    payload = SignPayload(signature=signature.to_dict())
    if save:
        json.dump(asdict(payload), save, indent=2)  # type: ignore
        console.print(f"Saved result to '{save.name}'")

    console.print("\nSending signature")
    task_id = send_payload(
        settings,
        URL.METADATA_SIGN.value,
        asdict(payload),
        "Metadata sign accepted.",
        "Metadata sign",
    )
    task_status(task_id, settings, "Metadata sign status:")
    console.print("\nMetadata Signed and sent to the API! 🔑\n")
