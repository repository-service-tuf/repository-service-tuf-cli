"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

Goals
-----
- use state-of-the-art securesystemslib Signer API only
- simplify (e.g. avoid custom/redundant abstractions over Metadata API)
- configure online signer location via uri attached to public key
  (for repository-service-tuf/repository-service-tuf-worker#427)

TODO
----
- finalize update
  - beautify (see pr comments)
  - api integration
  - cli options to save payload, or send payload only
  - assert one valid signature before pushing / saving

- implement ceremony

"""

import time
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import click

# Magic import to unbreak `load_pem_private_key` - pyca/cryptography#10315
import cryptography.hazmat.backends.openssl.backend  # noqa: F401
from click import ClickException
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from requests import request
from requests.exceptions import RequestException
from rich.markdown import Markdown
from rich.prompt import Confirm, IntPrompt, InvalidResponse, Prompt
from rich.table import Table
from securesystemslib.exceptions import StorageError
from securesystemslib.signer import (
    CryptoSigner,
    Key,
    Signature,
    Signer,
    SSlibKey,
)
from tuf.api.metadata import (
    Metadata,
    Root,
    RootVerificationResult,
    Snapshot,
    Targets,
    Timestamp,
    UnsignedMetadataError,
)
from tuf.api.serialization import DeserializationError

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console, rstuf
from repository_service_tuf.helpers.api_client import URL as ROUTE

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

KEY_URI_FIELD = "x-rstuf-online-key-uri"
# TODO: Consider using "x-rstuf-" prefix
KEY_NAME_FIELD = "name"

# Use locale's appropriate date representation to display the expiry date.
EXPIRY_FORMAT = "%x"


class _PositiveIntPrompt(IntPrompt):
    validate_error_message = (
        "[prompt.invalid]Please enter a valid positive integer number"
    )

    def process_response(self, value: str) -> int:
        return_value: int = super().process_response(value)
        if return_value < 1:
            raise InvalidResponse(self.validate_error_message)
        return return_value


def _load_public_key_from_file() -> Key:
    """Prompt for path to local public key, load and return."""

    path = Prompt.ask("Please enter a public key path")
    with open(path, "rb") as f:
        public_pem = f.read()

    crypto = load_pem_public_key(public_pem)

    key = SSlibKey.from_crypto(crypto)

    return key


def _show_root_key_info(root: Root) -> None:
    """Pretty print root keys and threshold."""
    # TODO: Make prettier and useful
    root_role = root.get_delegated_role(Root.type)
    console.print(f"Current Threshold: {root_role.threshold}")
    console.print("Current Keys:")
    for keyid in root_role.keyids:
        key = root.get_key(keyid)
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, "")
        if name:
            name = f"(name: {name})"
        console.print(f"keyid: {keyid}", name)


def _add_root_keys(root: Root) -> None:
    """Prompt loop to add root keys.

    Loops until user exit and root has at least two keys."""

    root_role = root.get_delegated_role(Root.type)

    while True:
        min_keys = 2
        missing = max(0, min_keys - len(root_role.keyids))
        if missing:
            console.print(f"Please add at least {missing} more root key(s).")

        else:
            if not Confirm.ask("Do you want to add a root key?"):
                break

        try:
            new_key = _load_public_key_from_file()
        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        # Disallow re-adding a key even if it is for a different role.
        if new_key.keyid in root.keys:
            console.print("Key already in use.")
            continue

        while True:
            name = Prompt.ask("Please enter a key name")
            if not name:
                console.print("Key name cannot be empty.")
                continue

            if name in [
                key.unrecognized_fields.get(KEY_NAME_FIELD)
                for key in root.keys.values()
            ]:
                console.print("Key name already in use.")
                continue

            new_key.unrecognized_fields[KEY_NAME_FIELD] = name
            break

        root.add_key(new_key, Root.type)
        console.print(f"Added root key '{new_key.keyid}'")

        _show_root_key_info(root)


def _remove_root_keys(root: Root) -> None:
    """Prompt loop to remove root keys.

    Loops until no keys left or user exit (threshold is ignored)."""
    root_role = root.get_delegated_role(Root.type)

    while True:
        if not root_role.keyids:
            break

        if not Confirm.ask("Do you want to remove a root key?"):
            break

        keyid = Prompt.ask(
            "Choose key to remove", choices=sorted(root_role.keyids)
        )
        root.revoke_key(keyid, Root.type)
        console.print(f"Removed root key '{keyid}'")

        _show_root_key_info(root)


def _configure_root_keys(root: Root) -> None:
    """Prompt series with loop to add/remove root keys, and enter threshold.

    Loops until user exit (at least one root key must be set).

    """
    console.print("Root Key Configuration")

    # Get current keys
    root_role = root.get_delegated_role(Root.type)

    while True:
        _show_root_key_info(root)

        # Allow user to skip offline key change (assumes valid metadata)
        if not Confirm.ask("Do you want to change root keys or threshold?"):
            break

        # Remove keys regardless of threshold
        _remove_root_keys(root)

        # Add keys regardless of threshold (require 2)
        _add_root_keys(root)

        # Threshold update is optional, depending on the number of root keys
        # and the current threshold.
        max_threshold = len(root_role.keyids) - 1
        if root_role.threshold <= max_threshold:
            if not Confirm.ask(
                "Do you want to change the root signature threshold?"
            ):
                continue
            default_threshold = root_role.threshold
        else:
            default_threshold = max_threshold

        root_role.threshold = IntPrompt.ask(
            "Please enter a root signature threshold",
            choices=[str(i) for i in range(1, max_threshold + 1)],
            show_choices=False,
            default=default_threshold,
        )


def _configure_online_key(root: Root) -> None:
    """Prompt loop to change online key.

    Loops until user exit.
    """
    console.print("Online Key Configuration")

    while True:
        current_key = _get_online_key(root)

        # Show key
        # TODO: Make pretty and useful
        console.print("Current Key:")
        uri = current_key.unrecognized_fields.get(KEY_URI_FIELD, "")
        if uri:
            uri = f"(uri: '{uri}')"
        console.print(f"keyid: {current_key.keyid}", uri)

        # Allow user to skip online key change (assumes valid metadata)
        if not Confirm.ask("Do you want to change the online key?"):
            break

        # Load new key
        try:
            new_key = _load_public_key_from_file()

        except (OSError, ValueError) as e:
            console.print(f"Cannot load: {e}")
            continue

        # Disallow re-adding a key even if it is for a different role.
        if new_key.keyid in root.keys:
            console.print("Key already in use.")
            continue

        # For file-based keys we default to a "relative file path uri" using
        # keyid as filename. The online signing key must be made available to
        # the worker under that filename. Additionally, a base path to the file
        # can be specified via container configuration.
        # see repository-service-tuf/repository-service-tuf#580 for details
        uri = f"fn:{new_key.keyid}"

        new_key.unrecognized_fields[KEY_URI_FIELD] = uri

        # Remove current and add new key
        for role_name in ONLINE_ROLE_NAMES:
            root.revoke_key(current_key.keyid, role_name)
            root.add_key(new_key, role_name)

        console.print(f"Configured online key: '{new_key.keyid}'")


def _configure_expiry(root: Root) -> None:
    """Prompt loop to configure root expiry.

    Loops until user exit and metadata is not expired.
    """
    console.print("Expiration Date Configuration")

    while True:
        if root.is_expired():
            console.print(
                f"Root has expired on {root.expires:{EXPIRY_FORMAT}}"
            )
        else:
            console.print(f"Root expires on {root.expires:{EXPIRY_FORMAT}}")
            if not Confirm.ask("Do you want to change the expiry date?"):
                break

        days = _PositiveIntPrompt.ask(
            "Please enter number of days from now, when root should expire"
        )

        root.expires = datetime.utcnow() + timedelta(days=days)
        console.print(f"Changed root to expire in {days} days")


def _load_signer(public_key: Key) -> Signer:
    """Ask for details to load signer, load and return."""
    path = Prompt.ask("Please enter path to encrypted local private key")

    with open(path, "rb") as f:
        private_pem = f.read()

    password = Prompt.ask("Please enter password", password=True)
    private_key = load_pem_private_key(private_pem, password.encode())
    return CryptoSigner(private_key, public_key)


def _show_missing_signatures(results: RootVerificationResult) -> None:
    results_to_show = [results.first]
    # Show only one result, if the same number of signatures from the same set
    # of keys is missing in both.
    if (
        results.second.unsigned != results.first.unsigned
        or results.second.missing != results.first.missing
    ):
        results_to_show.append(results.second)

    for result in results_to_show:
        title = f"Please add {result.missing} more signature(s) from any of "
        key_table = Table("ID", "Name", title=title)

        for keyid, key in result.unsigned.items():
            name = key.unrecognized_fields.get(KEY_NAME_FIELD)
            key_table.add_row(keyid, name)

        console.print(key_table)


def _get_missing_keys(results: RootVerificationResult) -> dict[str, Key]:
    missing_keys = {}
    # Use only those keys to sign, whose signatures are effectively missing.
    # This also means the cli can't be used to sign beyond the threshold.
    if not results.first.verified:
        missing_keys.update(results.first.unsigned)

    if not results.second.verified:
        missing_keys.update(results.second.unsigned)

    return missing_keys


def _sign_multiple(
    metadata: Metadata[Root],
    prev_root: Optional[Root],
) -> Optional[list[Signature]]:
    """Prompt loop to add signatures to root.

    Prints metadata for review once, and signature requirements.
    Loops until fully signed or user exit.
    """
    signatures: List[Signature] = []
    show_metadata = True
    while True:
        results = metadata.signed.get_root_verification_result(
            prev_root,
            metadata.signed_bytes,
            metadata.signatures,
        )

        if results.verified:
            console.print("Metadata is fully signed.")
            return signatures

        # Show metadata for review once
        if show_metadata:
            _show(metadata.signed)
            show_metadata = False

        _show_missing_signatures(results)
        missing_keys = _get_missing_keys(results)
        # Loop until signing success or user exit
        while True:
            if not Confirm.ask("Do you want to sign?"):
                return signatures

            signature = _sign(metadata, missing_keys)
            if signature:
                signatures.append(signature)
                break


def _sign_one(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Optional[Signature]:
    """Prompt loop to add one signature.

    Return None, if metadata is already fully missing.
    Otherwise, loop until success and returns the added signature.
    """
    results = metadata.signed.get_root_verification_result(
        prev_root,
        metadata.signed_bytes,
        metadata.signatures,
    )

    if results.verified:
        console.print("Metadata is fully signed.")
        return None

    missing_keys = _get_missing_keys(results)

    _show(metadata.signed)
    _show_missing_signatures(results)

    # Loop until success
    signature = None
    while not signature:
        signature = _sign(metadata, missing_keys)

    return signature


def _sign(metadata: Metadata, keys: Dict[str, Key]) -> Optional[Signature]:
    """Prompt for signing key and sign.

    Return Signature or None, if signing fails.
    """
    signature = None
    # TODO: Make sure keyid / name is not truncated in key table.
    # TODO: Check name collision?
    # TODO: Support keyid prefix?
    # -> Then we'd also need to check for collision. Or, should we just enforce
    #    adding mandatory unique names in bootstrap/update cli, and use full
    #    keyids as fallback?
    choices = {}
    for keyid, key in keys.items():
        choices[keyid] = key
        if name := key.unrecognized_fields.get(KEY_NAME_FIELD):
            choices[name] = key

    choice = Prompt.ask(
        "Please choose signing key by entering keyid or name",
        choices=list(choices),
        show_choices=False,
    )
    key = choices[choice]
    try:
        signer = _load_signer(key)
        signature = metadata.sign(signer, append=True)
        console.print(f"Signed metadata with key '{choice}'")

    except (ValueError, OSError, UnsignedMetadataError) as e:
        console.print(f"Cannot sign metadata with key '{choice}': {e}")

    return signature


def _load(prompt: str) -> Metadata[Root]:
    """Prompt loop to load root from file.

    Loop until success.
    """
    while True:
        path = Prompt.ask(prompt)
        try:
            metadata = Metadata[Root].from_file(path)
            break

        except (StorageError, DeserializationError) as e:
            console.print(f"Cannot load: {e}")

    return metadata


def _save(metadata: Metadata[Root]):
    """Prompt loop to save root to file.

    Loop until success or user exit.
    """
    while Confirm.ask("Save?"):
        path = Prompt.ask("Enter path to save root", default="root.json")
        try:
            metadata.to_file(path)
            console.print(f"Saved to '{path}'...")
            break

        except StorageError as e:
            console.print(f"Cannot save: {e}")


def _get_root_keys(root: Root) -> List[Key]:
    return [root.get_key(keyid) for keyid in root.roles[Root.type].keyids]


def _get_online_key(root: Root) -> Key:
    # TODO: assert all online roles have the same and only one keyid
    return root.get_key(root.roles[Timestamp.type].keyids[0])


def _show(root: Root):
    """Pretty print root metadata."""

    key_table = Table("Role", "ID", "Name", "Signing Scheme", "Public Value")
    for key in _get_root_keys(root):
        public_value = key.keyval["public"]  # SSlibKey-specific
        name = key.unrecognized_fields.get(KEY_NAME_FIELD)
        key_table.add_row("Root", key.keyid, name, key.scheme, public_value)
    key = _get_online_key(root)
    key_table.add_row(
        "Online", key.keyid, "", key.scheme, key.keyval["public"]
    )

    root_table = Table("Infos", "Keys", title="Root Metadata")
    root_table.add_row(
        (
            f"Expiration: {root.expires:%x}\n"
            f"Threshold: {root.roles[Root.type].threshold}"
        ),
        key_table,
    )

    console.print(root_table)


def _request(method: str, url: str, **kwargs: Any) -> Dict[str, Any]:
    """HTTP requests helper.

    Returns deserialized contents, and raises on error.
    """
    response = request(method, url, **kwargs)
    response.raise_for_status()
    response_data = response.json()["data"]
    return response_data


def _urljoin(server: str, route: str) -> str:
    """Very basic urljoin - adds slash separator if missing."""
    if not server.endswith("/"):
        server += "/"
    return server + route


def _wait_for_success(url: str) -> None:
    """Poll task API indefinitely until async task finishes.

    Raises RuntimeError, if task fails.
    """
    while True:
        response_data = _request("get", url)
        state = response_data["state"]

        if state in ["PENDING", "RECEIVED", "STARTED", "RUNNING"]:
            time.sleep(2)
            continue

        if state == "SUCCESS":
            if response_data["result"]["status"]:
                break

        raise RuntimeError(response_data)


def _fetch_metadata(
    url: str,
) -> Tuple[Optional[Metadata[Root]], Optional[Root]]:
    """Fetch from Metadata Sign API."""
    response_data = _request("get", url)
    metadata = response_data["metadata"]
    root_data = metadata.get("root")

    root_md = None
    prev_root = None
    if root_data:
        root_md = Metadata[Root].from_dict(root_data)
        if root_md.signed.version > 1:
            prev_root_data = metadata["trusted_root"]
            prev_root_md = Metadata[Root].from_dict(prev_root_data)
            prev_root = prev_root_md.signed

    return root_md, prev_root


def _push_signature(url: str, signature: Signature) -> str:
    """Post signature and wait for success of async task."""
    request_data = {"role": "root", "signature": signature.to_dict()}
    response_data = _request("post", url, json=request_data)
    task_id = response_data["task_id"]
    return task_id


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
def update() -> None:
    """Update root metadata and bump version.

    Will ask for root metadata, public key paths, and signing key paths.
    """
    console.print("Root Metadata Update")
    # Load
    current_root_md = _load("Enter path to root to update")
    new_root = deepcopy(current_root_md.signed)

    # Update
    _configure_expiry(new_root)
    _configure_root_keys(new_root)
    _configure_online_key(new_root)

    # Sign and save (if changed)
    if new_root == current_root_md.signed:
        console.print("Not saving unchanged metadata.")
    else:
        new_root.version += 1
        new_root_md = Metadata(new_root)
        _sign_multiple(new_root_md, current_root_md.signed)
        _save(new_root_md)

    console.print("Bye.")


@admin2.command()  # type: ignore
@click.option(
    "--api-server",
    help="URL to the RSTUF API.",
    required=True,
)
def sign(api_server: str) -> None:
    """Add one signature to root metadata."""
    console.print("\n", Markdown("# Metadata Signing Tool"))

    sign_url = _urljoin(api_server, ROUTE.METADATA_SIGN.value)
    try:
        root_md, prev_root = _fetch_metadata(sign_url)
    except RequestException as e:
        raise ClickException(str(e))

    if not root_md:
        console.print(f"Nothing to sign on {api_server}.")

    else:
        signature = _sign_one(root_md, prev_root)
        if signature:
            try:
                task_id = _push_signature(sign_url, signature)
                task_url = _urljoin(api_server, ROUTE.TASK.value) + task_id
                _wait_for_success(task_url)
            except (RequestException, RuntimeError) as e:
                raise ClickException(str(e))
