"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

TODO
----
- implement ceremony
- implement update

"""

import time
from typing import Any, Dict, List, Optional, Tuple

import click

# Magic import to unbreak `load_pem_private_key` - pyca/cryptography#10315
import cryptography.hazmat.backends.openssl.backend  # noqa: F401
from click import ClickException
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from requests import request
from requests.exceptions import RequestException
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.table import Table
from securesystemslib.signer import CryptoSigner, Key, Signature, Signer
from tuf.api.metadata import (
    Metadata,
    Root,
    RootVerificationResult,
    Timestamp,
    UnsignedMetadataError,
)

from repository_service_tuf.cli import console, rstuf
from repository_service_tuf.helpers.api_client import URL as ROUTE


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
            name = key.unrecognized_fields.get("name")
            key_table.add_row(keyid, name)

        console.print(key_table)


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

    keys_to_use = {}
    # Use only those keys to sign, whose signatures are effectively missing.
    # This also means the cli can't be used to sign beyond the threshold.
    if not results.first.verified:
        keys_to_use.update(results.first.unsigned)

    if not results.second.verified:
        keys_to_use.update(results.second.unsigned)

    _show(metadata.signed)
    _show_missing_signatures(results)

    # Loop until success
    signature = None
    while not signature:
        signature = _sign(metadata, keys_to_use)

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
        if name := key.unrecognized_fields.get("name"):
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
        name = key.unrecognized_fields.get("name")
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
