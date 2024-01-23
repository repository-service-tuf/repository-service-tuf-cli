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
- implement ceremony
- implement update
- polish enough so that reviewers can try it out
- Integrate with existing admin cli

"""
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from rich.pretty import pprint
from rich.prompt import Confirm, Prompt
from securesystemslib.exceptions import StorageError
from securesystemslib.signer import CryptoSigner, Key, Signature, Signer
from tuf.api.metadata import Metadata, Root, UnsignedMetadataError
from tuf.api.serialization import DeserializationError

from repository_service_tuf.cli import console, rstuf


def _load_signer(public_key: Key) -> Signer:
    """Ask for details to load signer, load and return."""
    # TODO: Give choice -> hsm, sigstore, ...

    # TODO: clarify supported key types, format
    path = Prompt.ask("Enter path to encrypted local private key")

    with open(path, "rb") as f:
        private_pem = f.read()

    password = Prompt.ask("Enter password", password=True)
    private_key = load_pem_private_key(private_pem, password.encode())
    return CryptoSigner(private_key, public_key)


def _get_verification_result(
    delegator: Root, delegate: Metadata[Root]
) -> Tuple[Dict[str, Key], str]:
    """Get opinionated verification result.

    TODO: consider upstreaming features to `get_verification_result`:
    - return keys (e.g. as dict), not keyids!
    - missing signature count is convenient, but not necessary
    - could also just return threshold
    (IIRC threshold was removed from result, because it can't be unioned.
     Maybe threshold in the result is more useful, than the union method.)

    Returns dict of unused keys and a message, to tell how many signatures are
    missing and from which keys. Empty message means fully signed.
    """
    result = delegator.get_verification_result(
        Root.type, delegate.signed_bytes, delegate.signatures
    )
    msg = ""
    if not result.verified:
        missing = delegator.roles[Root.type].threshold - len(result.signed)
        msg = (
            f"need {missing} signature(s) from any of "
            f"{sorted(result.unsigned)}"
        )

    unused_keys = {
        keyid: delegator.get_key(keyid) for keyid in result.unsigned
    }

    return unused_keys, msg


def _get_combined_verification_result(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Tuple[Dict[str, Key], str]:
    """Get combined verification results from previous and current root."""
    unused_keys, missing_sig_msg = _get_verification_result(
        metadata.signed, metadata
    )
    if prev_root:
        prev_keys, prev_msg = _get_verification_result(prev_root, metadata)
        unused_keys.update(prev_keys)

        # Combine "missing signatures" messages from old and new root:
        # - show only non-empty message (filter)
        # - show only one message, if both are equal (set)
        missing_sig_msg = "\n".join(
            filter(None, sorted({missing_sig_msg, prev_msg}))
        )
    return unused_keys, missing_sig_msg


def _sign_one(
    metadata: Metadata[Root], prev_root: Optional[Root]
) -> Optional[Signature]:
    """Prompt loop to add one signature.

    Return None, if metadata is already fully missing.
    Otherwise, loop until success and returns the added signature.
    """
    unused_keys, missing_sig_msg = _get_combined_verification_result(
        metadata, prev_root
    )
    if not missing_sig_msg:
        console.print("Metadata fully signed.")
        return None

    _show(metadata.signed)
    console.print(missing_sig_msg)

    # Loop until success
    signature = None
    while not signature:
        signature = _sign(metadata, unused_keys)

    return signature


def _sign(metadata: Metadata, keys: Dict[str, Key]) -> Optional[Signature]:
    """Prompt for signing key and sign.

    Return Signature or None, if signing fails.
    """
    signature = None
    keyid = Prompt.ask("Choose key", choices=sorted(keys))
    try:
        signer = _load_signer(keys[keyid])
        signature = metadata.sign(signer, append=True)
        console.print(f"Signed with key {keyid}")

    except (ValueError, OSError, UnsignedMetadataError) as e:
        console.print(f"Cannot sign: {e}")

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


def _show(root: Root):
    """Pretty print root metadata."""
    pprint(root.to_dict())


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


@rstuf.group()  # type: ignore
def admin2():
    """POC: alternative admin interface"""


@admin2.command()  # type: ignore
def sign() -> None:
    """Add one signature to root metadata.

    Will ask for root metadata and signing key path.
    """
    # 1. Load
    root_md = _load("Enter path to root to sign")
    prev_root = None
    if root_md.signed.version > 1:
        prev_root_md = _load("Enter path to previous root")
        prev_root = prev_root_md.signed

    # 2. Add signature, if missing
    signature = _sign_one(root_md, prev_root)

    # 3. Save, if signature was added
    if signature:
        _save(root_md)

    console.print("Bye.")
