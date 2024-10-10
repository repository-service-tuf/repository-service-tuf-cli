# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from dataclasses import asdict
from typing import Any, Dict, Optional

import click
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
    SignPayload,
    Targets,
    _add_signature_prompt,
    _filter_root_verification_results,
    _get_pending_roles,
    _parse_pending_data,
    _print_keys_for_signing,
    _print_root,
    _print_targets,
    _select_key,
    _select_role,
)
from repository_service_tuf.cli.admin.metadata import metadata
from repository_service_tuf.helpers.api_client import (
    URL,
    send_payload,
    task_status,
)

DEFAULT_PATH = "sign-payload.json"


# Allow group to run without subcommand
@metadata.group(invoke_without_command=True)
@click.option(
    "--in",
    "input",
    help=(
        "Input file containing the JSON response from the "
        "'GET /api/v1/metadata/sign' RSTUF API endpoint."
    ),
    type=click.File("r"),
    required=False,
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
    help="Run sign in dry-run mode without sending result to API. ",
)
@click.pass_context
def sign(
    context: click.Context,
    input: Optional[click.File],
    out: Optional[click.File],
    dry_run: bool,
) -> None:
    """
    Perform sign for pending event and send result to API.

    * If `--in FILENAME` is passed, input is not read from API but from local
    FILENAME.

    * If `--out [FILENAME]` is passed, result is written to local FILENAME
    (in addition to being sent to API).

    * If `--dry-run` is passed, result is not sent to API.
    You can still pass `--out [FILENAME]` to store the result locally.

    * If `--in` and `--dry-run` are passed, `--api-server` admin option and
    `SERVER` from config will be ignored.
    """
    console.print("\n", Markdown("# Metadata Signing Tool"))
    settings = context.obj["settings"]
    # Make sure there is a way to get a DAS metadata for signing.
    if settings.get("SERVER") is None and input is None:
        raise click.ClickException(
            "Either '--api-server' admin option/'SERVER' in RSTUF config or "
            "'--in' needed"
        )

    # Make sure user understands that result will be send to the API and if the
    # the user wants something else should use '--dry-run'.
    if not settings.get("SERVER") and not dry_run:
        raise click.ClickException(
            "Either '--api-server' admin option/'SERVER' in RSTUF config or "
            "'--dry-run' needed"
        )
    ###########################################################################
    # Load roots
    pending_roles: Dict[str, Dict[str, Any]]
    if input:
        pending_roles = _parse_pending_data(json.load(input))  # type: ignore
    else:
        pending_roles = _get_pending_roles(settings)

    console.print("\nSelect a role to sign:")
    role = _select_role(pending_roles)
    role_md = Metadata.from_dict(pending_roles[role])

    if role_md.signed.type == Root.type:
        version = role_md.signed.version
        prev_root = None
        if pending_roles.get("trusted_root"):
            prev_root = Metadata[Root].from_dict(pending_roles["trusted_root"])

        if version > 1 and not prev_root:
            raise click.ClickException(
                f"Previous root v{version-1} needed "
                f"to sign root v{version}."
            )

        #######################################################################
        # Verify signatures
        root_result = role_md.signed.get_root_verification_result(
            prev_root.signed if prev_root is not None else None,
            role_md.signed_bytes,
            role_md.signatures,
        )
        if root_result.verified:
            raise click.ClickException("Metadata already fully signed.")

        #######################################################################
        # Review metadata
        console.print(Markdown("## Review metadata to be signed"))
        _print_root(role_md.signed)

        #######################################################################
        # Sign metadata
        console.print(Markdown("## Sign"))
        results = _filter_root_verification_results(root_result)
        keys = _print_keys_for_signing(results)
        console.print(Markdown("Select key for signing:"))
        key = _select_key(keys)
        signature = _add_signature_prompt(role_md, key)

    else:
        targets = Metadata[Targets].from_dict(pending_roles["trusted_targets"])
        # sign Targets metadata
        console.print(Markdown("## metadata to be signed"))
        _print_targets(targets.signed)
        keys = []
        if targets.signed.delegations is None:
            raise click.ClickException("No custom delegations")

        if targets.signed.delegations.roles is None:
            raise click.ClickException("No roles  in delegations")

        for keyid in targets.signed.delegations.roles[role].keyids:
            if keyid not in role_md.signatures:
                keys.append(targets.signed.delegations.keys[keyid])

        key = _select_key(keys)
        signature = _add_signature_prompt(role_md, key)

    ###########################################################################
    # Send payload to the API and/or save it locally

    payload = SignPayload(signature=signature.to_dict(), role=role)
    if out:
        json.dump(asdict(payload), out, indent=2)  # type: ignore
        console.print(f"Saved result to '{out.name}'")

    if settings.get("SERVER") and not dry_run:
        console.print(f"\nSending signature to {settings.SERVER}")
        task_id = send_payload(
            settings=settings,
            url=URL.METADATA_SIGN.value,
            payload=asdict(payload),
            expected_msg="Metadata sign accepted.",
            command_name="Metadata sign",
        )
        task_status(task_id, settings, "Metadata sign status:")
        console.print("\nMetadata Signed and sent to the API! 🔑\n")
