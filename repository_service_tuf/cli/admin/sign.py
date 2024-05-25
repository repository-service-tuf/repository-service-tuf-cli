# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from dataclasses import asdict
from typing import Any, Dict, Optional

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
)
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    request_server,
    send_payload,
    task_status,
)
from repository_service_tuf.helpers.tuf import save_payload


def _parse_pending_data(pending_roles_resp: Dict[str, Any]) -> Dict[str, Any]:
    data = pending_roles_resp.get("data")
    if data is None:
        error = "'data' field missing from api server response/file input"
        raise click.ClickException(error)

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
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.option(
    "--save",
    "-s",
    is_flag=False,
    flag_value=DEFAULT_PATH,
    help=f"Write json result to FILENAME (default: '{DEFAULT_PATH}')",
    type=click.File("w"),
)
@click.argument(
    "signing_json_input_file",
    required=False,
    type=click.File("rb"),
)
@click.pass_context
def sign(
    context: Any,
    api_server: Optional[str],
    save: Optional[click.File],
    signing_json_input_file: Optional[click.File],
) -> None:
    """
    Add one signature to root metadata.

    There are two ways to use this command:

    1) utilizing access to the RSTUF API and signing pending metadata roles

    2) provide a local file using the 'SIGNING_JSON_INPUT_FILE' argument

    The result of this command will be saved locally in a 'sign-payload.json'
    file if '--api-server' is not provided or at custom path if '--save' is
    used.

    When using method 2:

    - 'SIGNING_JSON_INPUT_FILE' must be a file containing the JSON response
    from the 'GET /api/v1/metadata/sign' API endpoint.

    - '--api-server' will be ignored.
    """
    console.print("\n", Markdown("# Metadata Signing Tool"))
    settings = context.obj["settings"]
    if api_server:
        settings.SERVER = api_server
    if settings.get("SERVER") is None and signing_json_input_file is None:
        error = "Either '--api-sever' or 'SIGNING_JSON_INPUT_FILE' must be set"
        raise click.ClickException(error)
    ###########################################################################
    # Load roots
    pending_roles: Dict[str, Dict[str, Any]]
    if signing_json_input_file:
        pending_roles = _parse_pending_data(json.load(signing_json_input_file))  # type: ignore  # noqa
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
    key_idx = _choose_signing_key_prompt(len(keys), allow_skip=False)
    key = keys[key_idx - 1]
    signature = _add_signature_prompt(root_md, key)

    ###########################################################################
    # Send payload to the API and save it locally
    payload = SignPayload(signature=signature.to_dict())
    if settings.get("SERVER"):
        console.print(f"\nSending signature to {settings.SERVER}")
        task_id = send_payload(
            settings,
            URL.METADATA_SIGN.value,
            asdict(payload),
            "Metadata sign accepted.",
            "Metadata sign",
        )
        task_status(task_id, settings, "Metadata sign status:")
        console.print("\nMetadata Signed and sent to the API! 🔑\n")

    if save or not api_server:
        path = save.name if save is not None else DEFAULT_PATH
        save_payload(path, asdict(payload))
        console.print(f"Saved result to '{path}'")
