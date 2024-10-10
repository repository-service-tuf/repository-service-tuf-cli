# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import enum
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

import beaupy  # type: ignore
import click

# Magic import to unbreak `load_pem_private_key` - pyca/cryptography#10315
import cryptography.hazmat.backends.openssl.backend  # noqa: F401
import requests
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from rich.json import JSON
from rich.markdown import Markdown
from rich.prompt import Confirm, IntPrompt, InvalidResponse, Prompt
from rich.table import Table
from securesystemslib.formats import encode_canonical
from securesystemslib.hash import digest
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    AWSSigner,
    AzureSigner,
    CryptoSigner,
    GCPSigner,
    Key,
    Signature,
    SigstoreKey,
    SigstoreSigner,
    SSlibKey,
    VaultSigner,
)
from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    Root,
    RootVerificationResult,
    Snapshot,
    Targets,
    Timestamp,
    UnsignedMetadataError,
    VerificationResult,
)
from tuf.ngclient.updater import Updater

# TODO: Should we use the global rstuf console exclusively? We do use it for
# `console.print`, but not with `Confirm/Prompt.ask`. The latter uses a default
# console from `rich`. Using a single console everywhere would makes custom
# configuration or, more importantly, patching in tests easier:
# https://rich.readthedocs.io/en/stable/console.html#console-api
# https://rich.readthedocs.io/en/stable/console.html#capturing-output
from repository_service_tuf.cli import console
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    request_server,
)

ONLINE_ROLE_NAMES = {Timestamp.type, Snapshot.type, Targets.type}

KEY_URI_FIELD = "x-rstuf-online-key-uri"
KEY_NAME_FIELD = "x-rstuf-key-name"

# Use locale's appropriate date representation to display the expiry date.
EXPIRY_FORMAT = "%x"

DEFAULT_EXPIRY = {
    "root": 365,
    "timestamp": 1,
    "snapshot": 1,
    "targets": 365,
    "bins": 1,
}
DEFAULT_BINS_NUMBER = 256

# Sigstore issuers supported by RSTUF
SIGSTORE_ISSUERS = [
    "https://github.com/login/oauth",
    "https://login.microsoft.com",
    "https://accounts.google.com",
]

# SecureSystemsLib doesn't support SigstoreKey by default.
KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("sigstore-oidc", "Fulcio"): SigstoreKey,
    }
)


class SIGNERS(str, enum.Enum):
    @classmethod
    def values(self) -> List[str]:
        return [e.value for e in self]


# Root signers supported by RSTUF
class ROOT_SIGNERS(SIGNERS):
    KEY_PEM = "Key PEM File"
    SIGSTORE = "Sigstore"


class ONLINE_SIGNERS(SIGNERS):
    AWSKMS = "AWS KMS"
    GCPKMS = "Google Cloud KMS"
    AZKMS = "Azure KMS"
    HV = "HashiCorp Vault"
    KEY_PEM = "Key PEM File"


class DELEGATIONS_TYPE(str, enum.Enum):
    BINS = "Bins (online key only)"
    CUSTOM_DELEGATIONS = "Custom Delegations (online/offline key)"

    @classmethod
    def values(cls) -> List[str]:
        return [e.value for e in cls]


@dataclass
class _Settings:
    """Internal data container to gather online role settings from prompt."""

    timestamp_expiry: int
    snapshot_expiry: int
    targets_expiry: int
    bins_expiry: Optional[int] = None
    bins_number: Optional[int] = None
    delegations: Optional[Delegations] = None


@dataclass
class Role:
    expiration: int


@dataclass
class BinsRole(Role):
    number_of_delegated_bins: int


@dataclass
class Roles:
    root: Role
    timestamp: Role
    snapshot: Role
    targets: Role
    bins: Optional[BinsRole] = None
    delegations: Optional[Dict[str, Any]] = None


@dataclass
class Settings:
    roles: Roles


@dataclass
class Metadatas:  # accept bad spelling to disambiguate with Metadata
    root: dict[str, Any]


@dataclass
class CeremonyPayload:
    settings: "Settings"
    metadata: "Metadatas"
    timeout: int = 300


@dataclass
class UpdatePayload:
    metadata: "Metadatas"


@dataclass
class SignPayload:
    signature: dict[str, str]
    role: str = "root"


##############################################################################
# Prompt and dialog helpers
class _PositiveIntPrompt(IntPrompt):
    validate_error_message = (
        "[prompt.invalid]Please enter a valid positive integer number"
    )

    def process_response(self, value: str) -> int:
        return_value: int = super().process_response(value)
        if return_value < 1:
            raise InvalidResponse(self.validate_error_message)
        return return_value


class _MoreThan1Prompt(IntPrompt):
    validate_error_message = "[prompt.invalid]Please enter threshold above 1"

    def process_response(self, value: str) -> int:
        return_value: int = super().process_response(value)
        if return_value < 2:
            raise InvalidResponse(self.validate_error_message)
        return return_value


def _load_signer_from_file_prompt(public_key: SSlibKey) -> CryptoSigner:
    """Prompt for path to private key and password, return Signer."""
    name_value = public_key.unrecognized_fields.get(KEY_NAME_FIELD)
    name_str = f"[green]{name_value}[/]"
    path = Prompt.ask(
        f"\nPlease enter [yellow]path[/] to encrypted private key '{name_str}'"
    )

    with open(path, "rb") as f:
        private_pem = f.read()

    # Because of click.prompt we are required to use click.style()
    name_str = click.style(name_value, fg="green")
    password_str = click.style("password", fg="yellow")
    password = click.prompt(
        f"\nPlease enter {password_str} to encrypted private key '{name_str}'",
        hide_input=True,
    )
    private_key = load_pem_private_key(private_pem, password.encode())
    return CryptoSigner(private_key, public_key)


def _load_key_from_file_prompt() -> SSlibKey:
    """Prompt for path to public key, return Key."""
    path = Prompt.ask("\nPlease enter path to public key")
    with open(path, "rb") as f:
        public_pem = f.read()

    crypto = load_pem_public_key(public_pem)

    key = SSlibKey.from_crypto(crypto)

    return key


def _new_keyid(key: Key) -> str:
    data: bytes = encode_canonical(key.to_dict()).encode()
    hasher = digest("sha256")
    hasher.update(data)
    return hasher.hexdigest()


def _load_key_from_sigstore_prompt() -> Optional[Key]:
    console.print(
        "\n:warning: Sigstore is not supported by all TUF Clients.\n",
        justify="left",
        style="italic",
    )
    identity = Prompt.ask("Please enter Sigstore identity")
    console.print(
        "\n:warning: RSTUF only support Sigstore public issuers.\n",
        justify="left",
        style="italic",
    )
    issuer = _select(SIGSTORE_ISSUERS)

    key = SigstoreKey(
        keyid="temp",
        keytype="sigstore-oidc",
        scheme="Fulcio",
        keyval={"issuer": issuer, "identity": identity},
        unrecognized_fields={KEY_NAME_FIELD: identity},
    )

    key.keyid = _new_keyid(key)

    return key


def _load_key_prompt(
    keys: Dict[str, Key],
    signer_type: Optional[str] = None,
    duplicate: Optional[bool] = True,
) -> Optional[Key]:
    """Prompt and return Key, or None on error or if key is already loaded."""
    try:
        if not signer_type:
            console.print("\nSelect a key type:")
            signer_type = _select(ROOT_SIGNERS.values())

        match signer_type:
            case ROOT_SIGNERS.KEY_PEM:
                key = _load_key_from_file_prompt()
            case ROOT_SIGNERS.SIGSTORE:
                key = _load_key_from_sigstore_prompt()

    except (OSError, ValueError) as e:
        console.print(f"Cannot load key: {e}")
        return None

    # Disallow re-adding a key even if it is for a different role.
    # TODO: disallow only within the same role
    if duplicate is False and key.keyid in keys:
        console.print("\nKey already in use.", style="bold red")
        return None

    return key


def _load_online_key_prompt(
    root: Root, signer_type: str
) -> Tuple[Optional[str], Optional[Key]]:
    """Prompt and return Key, or None on error or if key is already loaded."""
    try:
        match signer_type:
            case ONLINE_SIGNERS.KEY_PEM:
                key = _load_key_from_file_prompt()
                uri = f"fn:{key.keyid}"

            case ONLINE_SIGNERS.AWSKMS:
                uri, key = AWSSigner.import_(Prompt.ask("AWS KMS KeyID"))

            case ONLINE_SIGNERS.GCPKMS:
                uri, key = GCPSigner.import_(Prompt.ask("GCP KeyID"))

            case ONLINE_SIGNERS.HV:
                uri, key = VaultSigner.import_(
                    Prompt.ask("HashiCorp Key Name")
                )

            case ONLINE_SIGNERS.AZKMS:
                azure_vault_name = Prompt.ask("Azure Vault Name")
                azure_key_name = Prompt.ask("Azure Key Name")
                uri, key = AzureSigner.import_(
                    az_vault_name=azure_vault_name,
                    az_key_name=azure_key_name,
                )

    except (OSError, ValueError) as e:
        console.print(f"Cannot load key: {e}")
        return None, None

    # Disallow re-adding a key even if it is for a different role.
    if key.keyid in root.keys:
        console.print("\nKey already in use.", style="bold red")
        return None, None

    return uri, key


def _delegated_target_role_name_prompt() -> str:
    """Prompt for delegated target role name until success."""
    while True:
        name = Prompt.ask("Please enter delegated target role name")
        if not name:
            console.print("Role name cannot be empty.")
            continue
        break

    return name


def _key_name_prompt(
    keys: Dict[str, Key],
    name: Optional[str] = None,
    duplicate: Optional[bool] = False,
) -> str:
    """Prompt for key name until success."""
    while True:
        name = Prompt.ask("Please enter key name", default=name)
        if not name:
            console.print("Key name cannot be empty.")
            continue

        if duplicate is False and name in [
            k.unrecognized_fields.get(KEY_NAME_FIELD) for k in keys.values()
        ]:
            console.print("\nKey name already in use.", style="bold red")
            continue

        break

    return name


def _expiry_prompt(role: str) -> Tuple[int, datetime]:
    """Prompt for days until expiry for role, returns days and expiry date.

    Use per-role defaults from ExpirationSettings.
    """
    days = _PositiveIntPrompt.ask(
        f"Please enter days until expiry for '{role}' role",
        default=DEFAULT_EXPIRY.get(role, 1),
    )
    today = datetime.now(timezone.utc).replace(microsecond=0)
    date = today + timedelta(days=days)
    console.print(f"New expiry date is: {date:{EXPIRY_FORMAT}}")

    return days, date


def _settings_prompt() -> _Settings:
    """Prompt for expiry days of online roles and number of delegated bins."""
    timestamp_expiry, _ = _expiry_prompt("timestamp")
    snapshot_expiry, _ = _expiry_prompt("snapshot")
    targets_expiry, _ = _expiry_prompt("targets")

    return _Settings(
        timestamp_expiry,
        snapshot_expiry,
        targets_expiry,
    )


def _threshold_prompt(role: str) -> int:
    return _MoreThan1Prompt.ask(f"Please enter '{role}' threshold")


def _select(options: List[str]) -> str:
    return beaupy.select(options=options, cursor=">", cursor_style="cyan")


def _select_key(keys: List[Key]) -> Key:
    key_choices = {
        key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid): key
        for key in keys
    }
    sign_options = list(key_choices.keys())
    sign_options = [f"[green]{option}[/]" for option in sign_options]
    choice = _select(sign_options)
    # Remove beautification to get the actual key.
    choice = choice.removeprefix("[green]").removesuffix("[/]")
    return key_choices[choice]


def _select_role(roles: Dict[str, Dict[str, Any]]) -> str:
    roles_options = [x for x in roles if not x.startswith("trusted_")]
    choice = _select(roles_options)
    return choice


def _configure_root_keys_prompt(root: Root) -> None:
    """Prompt dialog to add or remove root key in passed root, until user exit.

    - Print if and how many root keys are missing to meet the threshold
    - Print current root keys
    - Prompt for user choice to add or remove key, or to skip (exit)
        - "continue" choice is only available, if threshold is met
        - "remove" choice is only available, if keys exist
        - "add" choice is only shown, if "remove" or "continue" is available,
          otherwise, we branch right into "add" dialog

    """
    while True:
        keys = _print_root_keys(root)

        threshold = root.roles[Root.type].threshold
        missing = max(0, threshold - len(keys))
        _print_missing_key_info(threshold, missing)

        # build the action choices
        action_options = ["add", "remove"]
        if not missing:
            action_options.insert(0, "continue")

        # prompt for user choice
        if not keys:
            action = "add"

        else:
            action = _select(action_options)

        # apply choice
        match action:
            case "continue":
                break

            case "add":
                new_key = _load_key_prompt(root.keys)
                if not new_key:
                    continue

                name = _key_name_prompt(
                    root.keys, new_key.unrecognized_fields.get(KEY_NAME_FIELD)
                )
                new_key.unrecognized_fields[KEY_NAME_FIELD] = name
                root.add_key(new_key, Root.type)
                console.print(f"Added key '{name}'")

            case "remove":
                console.print("\nSelect a key to remove:")
                key = _select_key(keys)
                name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
                root.revoke_key(key.keyid, Root.type)
                console.print(f"Removed key '{name}'")


def _configure_online_key_prompt(root: Root) -> None:
    """Prompt dialog to set or optionally update the online key."""
    current_key = _get_online_key(root)
    if current_key:
        # TODO: Is the info even helpful?
        name = current_key.unrecognized_fields.get(
            KEY_NAME_FIELD, current_key.keyid
        )
        console.print(f"Current online key is: '{name}'")
        if not Confirm.ask(
            "Do you want to change the online key?", default=True
        ):
            return

    console.print("\nSelect Online Key type:")
    while True:
        online_key_signer = _select(ONLINE_SIGNERS.values())
        uri, new_key = _load_online_key_prompt(root, online_key_signer)

        if new_key:
            break

    name = _key_name_prompt(root.keys)
    new_key.unrecognized_fields[KEY_NAME_FIELD] = name
    new_key.unrecognized_fields[KEY_URI_FIELD] = uri

    for role_name in ONLINE_ROLE_NAMES:
        if current_key:
            root.revoke_key(current_key.keyid, role_name)
        root.add_key(new_key, role_name)

    console.print(f"Configured file-based online key: '{name}'")
    console.print(f"Expected private key file name is: '{new_key.keyid}'")


def _add_signature_prompt(metadata: Metadata, key: Key) -> Signature:
    """Prompt for signing key and add signature to metadata until success."""
    while True:
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
        try:
            if key.keytype == "sigstore-oidc":
                signer = SigstoreSigner.from_priv_key_uri(
                    "sigstore:?ambient=false", key
                )
            # Using Key PEM file
            else:
                signer = _load_signer_from_file_prompt(key)

            signature = metadata.sign(signer, append=True)
            break

        except (ValueError, OSError, UnsignedMetadataError) as e:
            console.print(f"Cannot sign metadata with key '{name}': {e}")

    console.print(f"Signed metadata with key '{name}'")
    return signature


def _add_root_signatures_prompt(
    root_md: Metadata[Root], prev_root: Optional[Root]
) -> None:
    # TODO: Add docstring
    while True:
        root_result = root_md.signed.get_root_verification_result(
            prev_root,
            root_md.signed_bytes,
            root_md.signatures,
        )
        if root_result.verified:
            console.print("Metadata is fully signed.")
            break

        results = _filter_root_verification_results(root_result)
        keys = _print_keys_for_signing(results)
        key_choices = {
            key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid): key
            for key in keys
        }
        sign_options = list(key_choices.keys())
        or_continue = ":"
        if bool(root_result.signed):
            or_continue = " or continue:"
            sign_options.insert(0, "continue")

        console.print(f"\nSelect a key for signing{or_continue}")
        choice = _select(sign_options)

        if choice == "continue":
            break

        _add_signature_prompt(root_md, key_choices[choice])


# Delegations
##############################################################################
def _path_prompt() -> str:
    """Prompt for path name until success."""
    console.print(
        "The 'path' delegates targets matching any path pattern.",
        style="italic",
    )
    while True:
        name = Prompt.ask("Please enter path")
        if not name:
            console.print("Path cannot be empty.")
            continue

        break

    return name


def _configure_delegations_paths(
    delegated_role: DelegatedRole,
) -> DelegatedRole:
    if delegated_role.paths is None:
        delegated_role.paths = []

    while True:
        console.print(f"\nCurrent paths for '{delegated_role.name}'")
        for path in delegated_role.paths:
            console.print(f"- '{path}'")

        if bool(delegated_role.paths) is False:
            delegated_role.paths.append(_path_prompt())
            continue

        # build the action choices
        action_options = ["continue", "add new path", "remove path"]
        console.print()
        action = _select(action_options)
        # apply choice
        match action:
            case "continue":
                break

            case "add new path":
                delegated_role.paths.append(_path_prompt())

            case "remove path":
                console.print()
                path = _select(delegated_role.paths)
                delegated_role.paths.remove(path)
                console.print(f"path '{path}' removed\n")

    return delegated_role


def _configure_delegations_keys(
    delegated_role: DelegatedRole, delegations: Delegations
) -> None:
    while True:
        for keyid, key in delegations.keys.items():
            if keyid in delegated_role.keyids:
                name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
                console.print(f"- '{name}'")

        missing = max(
            0,
            delegated_role.threshold
            - len(
                [
                    key
                    for key in delegations.keys
                    if key in delegated_role.keyids
                ]
            ),
        )
        _print_missing_key_info(delegated_role.threshold, missing)

        # build the action choices
        action_options = ["add", "remove"]
        if not missing:
            action_options.insert(0, "continue")

        # prompt for user choice
        if not delegations.keys:
            action = "add"

        else:
            action = _select(action_options)

        # apply choice
        match action:
            case "continue":
                break

            case "add":
                new_key = _load_key_prompt(delegations.keys, duplicate=True)
                if not new_key:
                    continue

                name = _key_name_prompt(
                    delegations.keys,
                    new_key.unrecognized_fields.get(KEY_NAME_FIELD),
                    duplicate=True,
                )
                new_key.unrecognized_fields[KEY_NAME_FIELD] = name
                delegations.keys[new_key.keyid] = new_key
                delegated_role.keyids.append(new_key.keyid)
                console.print(f"Added key '{name}'")

            case "remove":
                # TODO:
                # 1. List the key (by key name) for the role
                # 2. Remove the KeyID from delegated role
                # 3. Remove from delegation roles keys IF not
                #    used by another role
                raise NotImplementedError("TODO")


def _configure_delegations() -> Delegations:
    delegations = Delegations(keys={}, roles={})
    while True:
        if delegations.roles is None or len(delegations.roles) == 0:
            action = "add new delegation"

        else:
            _print_delegation(delegations)
            action = _select(
                ["continue", "add new delegation", "remove delegation"]
            )

        match action:
            case "continue":
                break

            case "add new delegation":
                if delegations.roles is None:
                    delegations.roles = {}
                name = _delegated_target_role_name_prompt()
                if delegations.roles.get(name):
                    if not Confirm.ask(
                        f"\nDelegation '{name}' exists. Do you want overwrite"
                        f" '{name}'"
                    ):
                        continue

                expire_days, _ = _expiry_prompt(name)
                # ##########################################################
                # Load the Public Keys used to sign the metadata
                delegated_role = DelegatedRole(
                    name=name,
                    threshold=1,
                    keyids=[],
                    terminating=True,
                    paths=[],
                    unrecognized_fields={"x-rstuf-expire-policy": expire_days},
                )
                _configure_delegations_paths(delegated_role)
                console.print("Select signing:")
                signing_method = _select(
                    ["Online Key (use the existing)", "Add Keys"]
                )
                if signing_method == "Add Keys":
                    delegated_role.threshold = _threshold_prompt(
                        delegated_role.name
                    )
                    _configure_delegations_keys(delegated_role, delegations)

                delegations.roles[delegated_role.name] = delegated_role

            case "remove delegation":
                if delegations.roles is None:
                    console.print("Delegations is empty")
                    continue

                role_name = _select(list(delegations.roles.keys()))
                removed_role = delegations.roles[role_name]

                delegations.roles.pop(role_name)
                in_use_keyids: List[str] = []

                for role in delegations.roles.values():
                    in_use_keyids += role.keyids

                for keyid in removed_role.keyids:
                    if keyid not in in_use_keyids:
                        delegations.keys.pop(keyid)

                console.print(f"Delegation '{role_name}' removed.")

    return delegations


def _configure_delegations_prompt(settings: _Settings) -> None:
    while True:
        console.print(
            Markdown(
                "### Delegations\n"
                "RSTUF supports two types of delegations:\n"
                "- **Bins**:\n"
                "Generates hash bin delegations and uses an online key for\n"
                "signing.\n"
                "- **Custom Delegations**:\n"
                "Allows the creation of delegated roles for specified paths,\n"
                " utilizing both offline and online keys."
            )
        )
        console.print()
        delegations_type = _select(DELEGATIONS_TYPE.values())
        if delegations_type is None:
            continue
        if delegations_type == DELEGATIONS_TYPE.BINS:
            bins_expiry, _ = _expiry_prompt("bins")
            bins_number = IntPrompt.ask(
                "Please enter number of delegated hash bins",
                default=DEFAULT_BINS_NUMBER,
                choices=[str(2**i) for i in range(1, 15)],
                show_default=True,
                show_choices=True,
            )

            settings.bins_expiry = bins_expiry
            settings.bins_number = bins_number
            break
        else:
            settings.delegations = _configure_delegations()
            break


##############################################################################
# Other helpers


def _get_root_keys(root: Root) -> Dict[str, Key]:
    return {
        keyid: root.get_key(keyid) for keyid in root.roles[Root.type].keyids
    }


def _get_online_key(root: Root) -> Optional[Key]:
    # TODO: assert all online roles have the same and only one keyid, or none
    key = None
    if root.roles[Timestamp.type].keyids:
        key = root.get_key(root.roles[Timestamp.type].keyids[0])

    return key


def _parse_pending_data(pending_roles_resp: Dict[str, Any]) -> Dict[str, Any]:
    data = pending_roles_resp.get("data", {})

    all_roles: Dict[str, Dict[str, Any]] = data.get("metadata", {})
    pending_roles = {
        k: v for k, v in all_roles.items() if not k.startswith("trusted_")
    }
    if len(pending_roles) == 0:
        raise click.ClickException("No metadata available for signing")

    if any(
        role["signed"]["_type"] not in [Root.type, Targets.type]
        for role in pending_roles.values()
    ):
        raise click.ClickException(
            "Supporting only root and targets pending role types"
        )

    return all_roles


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


def _print_root(root: Root):
    """Pretty print root metadata."""

    key_table = Table("Role", "Name", "Signing Scheme", "Public Value")
    for key in _get_root_keys(root).values():
        if isinstance(key, SigstoreKey):
            public_value = f"{key.keyval['identity']}@{key.keyval['issuer']}"
        else:
            public_value = key.keyval["public"]  # SSlibKey-specific

        name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
        key_table.add_row(
            "Root", f"[green]{name}[/]", key.scheme, public_value
        )

    key = _get_online_key(root)
    name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
    key_table.add_row(
        "Online", f"[green]{name}[/]", key.scheme, key.keyval["public"]
    )

    root_table = Table("Infos", "Keys", title="Root Metadata")
    root_table.add_row(
        (
            f"Expiration: {root.expires:%x}\n"
            f"Threshold: {root.roles[Root.type].threshold}\n"
            f"Version: {root.version}"
        ),
        key_table,
    )

    console.print(root_table)


def _print_targets(targets: Targets):
    """Pretty print targets metadata."""

    targets_table = Table("Version", "Artifacts")
    artifact_table = Table("Path", "Info", show_lines=True)

    for path, info in targets.targets.items():
        artifact_table.add_row(
            path, JSON.from_data(info.to_dict()), style="bold"
        )
    targets_table.add_row(str(targets.version), artifact_table)
    console.print(targets_table)


def _print_delegation(delegations: Delegations):
    """Pretty print target delegation metadata."""
    if delegations.roles is None:
        console.print("No delegations")
        return None

    delegations_table = Table(
        "Role Name",
        "Infos",
        "Keys",
        title="Delegation Metadata",
        show_lines=True,
    )

    for rolename, delegation in delegations.roles.items():
        key_table: Optional[Table] = None
        key_table = Table("ID", "Name", "Signing Scheme")
        for key in delegations.keys.values():
            if key.keyid in delegations.roles[rolename].keyids:
                name = key.unrecognized_fields.get(KEY_NAME_FIELD)
                key_table.add_row(key.keyid, name, key.scheme)

        if len(key_table.rows) == 0:
            key_table = None

        if delegation.paths is None:
            delegation.paths = []
        delegations_table.add_row(
            delegation.name,
            (
                f"Expiration: {delegation.unrecognized_fields['x-rstuf-expire-policy']}\n"  # noqa
                f"Threshold: {delegation.threshold}\n"
                f"Paths: {', '.join(delegation.paths)}"
            ),
            key_table or "Online Key",
        )

    console.print(delegations_table)


def _filter_root_verification_results(
    root_result: RootVerificationResult,
) -> list[VerificationResult]:
    """Filter unverified results with distinct relevant fields."""

    # 1. Filter unverified
    results: list[VerificationResult] = [
        r for r in (root_result.first, root_result.second) if not r.verified
    ]

    # 2. Filter distinct by 'unsigned' and 'missing' properties
    if len(results) == 2:
        if (root_result.first.unsigned == root_result.second.unsigned) and (
            root_result.first.missing == root_result.second.missing
        ):
            results = results[:1]

    return results


def _print_keys_for_signing(
    results: list[VerificationResult],
) -> list[Key]:
    """Print public keys eligible for signing and return in printed order.

    The indexed output can be used to choose a signing key (1-based).
    """
    keys: list[Key] = []
    for result in results:
        m = result.missing
        s = "s" if m > 1 else ""
        console.print(f"Info: {m} signature{s} missing from any of:")
        for key in result.unsigned.values():
            name = key.unrecognized_fields.get(KEY_NAME_FIELD, key.keyid)
            console.print(f"- [green]{name}[/]")
            keys.append(key)
        console.print()

    return keys


def _print_root_keys(root: Root) -> list[Key]:
    """Print current root keys and return in printed order.

    The indexed output can be used to choose a key (1-based).
    """
    keys: list[Key] = []
    keyids = root.roles[Root.type].keyids

    if keyids:
        console.print("\nCurrent signing keys:")

    for keyid in keyids:
        key = root.get_key(keyid)
        name = key.unrecognized_fields.get(KEY_NAME_FIELD, keyid)
        console.print(f"- '{name}'")
        keys.append(key)

    return keys


def _print_missing_key_info(threshold: int, missing: int) -> None:
    if missing:
        s = "s" if missing > 1 else ""
        console.print(
            f"\nInfo: {missing} key{s} missing for threshold {threshold}."
        )
    else:
        console.print(
            f"\nInfo: Threshold {threshold} is met, more keys can be added."
        )


def _warn_no_save():
    console.print(
        ":warning: ",
        "metadata result not sent to rstuf worker, use `-s` to save locally ",
        ":warning:",
        justify="center",
        style="italic",
    )


def _get_latest_md(metadata_url: str, role_name: str) -> Metadata:
    try:
        temp_dir = TemporaryDirectory()
        initial_root_url = f"{metadata_url}/1.root.json"
        response = requests.get(initial_root_url, timeout=300)
        if response.status_code != 200:
            raise click.ClickException(
                f"Cannot fetch initial root {initial_root_url}"
            )

        with open(f"{temp_dir.name}/root.json", "w") as f:
            f.write(response.text)

        updater = Updater(
            metadata_dir=temp_dir.name, metadata_base_url=metadata_url
        )
        updater.refresh()
        md_bytes = updater._load_local_metadata(role_name)
        metadata = Metadata.from_bytes(md_bytes)

        return metadata

    except (OSError, RepositoryError, DownloadError):
        raise click.ClickException(f"Problem fetching latest {role_name}")
