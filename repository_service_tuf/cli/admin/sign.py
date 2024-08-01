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
from repository_service_tuf.cli.admin import metadata
from repository_service_tuf.cli.admin.helpers import (
    Metadata,
    Root,
    SignPayload,
    _add_signature_prompt,
    _filter_root_verification_results,
    _print_keys_for_signing,
    _print_root,
    _select_key,
)
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    request_server,
    send_payload,
    task_status,
)


def _parse_pending_data(pending_roles_resp: Dict[str, Any]) -> Dict[str, Any]:
    data = pending_roles_resp.get("data", {})

    pending_roles: Dict[str, Dict[str, Any]] = data.get("metadata", {})
    if len(pending_roles) == 0:
        raise click.ClickException("No metadata available for signing")

    return pending_roles


def _get_pending_roles(settings: Any) -> Dict[str, Dict[str, Any]]:
    """Get dictionary of pending roles for signing."""
    response = request_server(
        settings.SERVER, URL.METADATA_SIGN.value, Methods.GET
    )
    if response.status_code != 200:
        raise click.ClickException(
            f"Failed to fetch metadata for signing. Error: {response.text}"
        )

    return _parse_pending_data(response.json())


DEFAULT_PATH = "sign-payload.json"


@metadata.command()  # type: ignore
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
    key = _select_key(keys)
    signature = _add_signature_prompt(root_md, key)

    ###########################################################################
    # Send payload to the API and/or save it locally

    payload = SignPayload(signature=signature.to_dict())
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
