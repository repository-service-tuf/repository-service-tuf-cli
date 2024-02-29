# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import base64
import copy
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple

import click
from cryptography.hazmat.primitives import serialization
from rich import prompt, table
from rich.console import Console
from securesystemslib.exceptions import (  # type: ignore
    CryptoError,
    Error,
    FormatError,
    StorageError,
)
from securesystemslib.interface import (  # type: ignore
    import_privatekey_from_file,
)
from securesystemslib.signer import Signer  # type: ignore
from securesystemslib.signer import SSlibSigner  # type: ignore
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME
from securesystemslib.signer import SSlibKey as Key  # type: ignore
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import SPECIFICATION_VERSION, Metadata, Role, Root
from tuf.api.serialization.json import JSONSerializer

from repository_service_tuf.constants import KeyType

console = Console()

SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)
BINS: str = "bins"


class Roles(Enum):
    ROOT = "root"
    TARGETS = "targets"
    SNAPSHOT = "snapshot"
    TIMESTAMP = "timestamp"
    BINS = "bins"


@dataclass
class RSTUFKey:
    key: dict = field(default_factory=dict)
    key_path: Optional[str] = None
    name: Optional[str] = None
    error: Optional[str] = None

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, RSTUFKey):
            return False

        return self.key.get("keyid") == other.key.get("keyid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.key,
            "key_path": self.key_path,
            "name": self.name,
        }


@dataclass
class BootstrapSetup:
    expiration: Dict[Roles, int]
    number_of_keys: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    threshold: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    number_of_delegated_bins: int = 256
    root_keys: Dict[str, RSTUFKey] = field(default_factory=Dict)
    online_key: RSTUFKey = field(default_factory=RSTUFKey)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"roles": {}}
        for role in Roles:
            if role.value == BINS:
                result["roles"][BINS] = {
                    "expiration": self.expiration[role],
                    "number_of_delegated_bins": self.number_of_delegated_bins,
                }
            else:
                result["roles"][role.value] = {
                    "expiration": self.expiration[role],
                }

        return result


class MetadataInfo:
    _new_md: Metadata
    signing_keys: Dict[str, RSTUFKey]  # required for signing
    _trusted_md: Metadata  # required to check for changes

    @property
    def threshold(self) -> int:
        return self._new_md.signed.roles[Root.type].threshold

    @threshold.setter
    def threshold(self, value: int) -> None:
        self._new_md.signed.roles[Root.type].threshold = value

    @property
    def type(self) -> str:
        return self._trusted_md.signed.type.capitalize()

    @property
    def expiration(self) -> datetime:
        return self._new_md.signed.expires

    @expiration.setter
    def expiration(self, value: datetime) -> None:
        self._new_md.signed.expires = value

    @property
    def expiration_str(self) -> str:
        return f"{self.expiration.strftime('%Y-%b-%d')}"

    @property
    def keys(self) -> List[Dict[str, Any]]:
        root_keys: List[Dict[str, Any]] = []
        for keyid in self._new_md.signed.roles["root"].keyids:
            key = self._new_md.signed.keys[keyid]
            key_dict = key.to_dict()
            key_dict["keyid"] = keyid
            key_dict["name"] = self._get_key_name(key)
            root_keys.append(key_dict)

        return root_keys

    @property
    def online_key(self) -> Dict[str, Any]:
        online_key_id = self._new_md.signed.roles["timestamp"].keyids[0]
        key_obj = self._new_md.signed.keys[online_key_id]
        online_key_dict = key_obj.to_dict()
        online_key_dict["keyid"] = online_key_id
        online_key_dict["name"] = self._get_key_name(key_obj)
        return online_key_dict

    def __init__(self, root_md: Metadata[Root]):
        self._new_md = root_md
        self.signing_keys = {}
        self._trusted_md = copy.deepcopy(self._new_md)

    @staticmethod
    def _get_key_name(key: Key) -> str:
        name = key.keyid[:7]
        if key.unrecognized_fields.get("name"):
            name = key.unrecognized_fields["name"]

        return name

    def _get_pending_and_used_keys(
        self,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Helper function that can be used to get all keys that have been used
        for signing and does that have not been yet.
        """
        used_keys_info: List[Dict[str, Any]] = []
        pending_keys_info: List[Dict[str, Any]] = []
        for key_info in self.keys:
            if key_info["keyid"] not in self._new_md.signatures:
                # Key has not been used for signing yet.
                pending_keys_info.append(key_info)
            else:
                # Key has been used for signing.
                used_keys_info.append(key_info)

        return used_keys_info, pending_keys_info

    def is_keyid_used(self, keyid: str) -> bool:
        """Check if keyid is used in root keys"""
        return keyid in self._new_md.signed.roles[Root.type].keyids

    def save_current_md_key(self, key: RSTUFKey):
        """Update internal information based on 'key' data."""
        tuf_key: Key = self._new_md.signed.keys[key.key["keyid"]]
        if tuf_key.unrecognized_fields.get("name"):
            key.name = tuf_key.unrecognized_fields["name"]

        self.signing_keys[key.key["keyid"]] = key

    def remove_key(self, key_name: str) -> bool:
        """Try to remove a root key and return status of the operation"""
        for keyid in self._new_md.signed.roles["root"].keyids:
            key = self._new_md.signed.keys[keyid]
            name = self._get_key_name(key)
            if name == key_name:
                self._new_md.signed.revoke_key(keyid, Root.type)
                return True

        return False

    def new_signing_keys_required(self):
        """
        Get the number of additional signing keys needed when taking into
        account the keys from the trusted root.
        """
        # Count only the signing keys still left in new_root
        signing_keys_amount = 0
        for keyid in self.signing_keys:
            if keyid in self._new_md.signed.roles["root"].keyids:
                signing_keys_amount += 1

        if self.threshold <= signing_keys_amount:
            return 0

        return self.threshold - signing_keys_amount

    def add_key(self, new_key: RSTUFKey) -> None:
        """Add a new root key."""
        tuf_key = Key.from_securesystemslib_key(new_key.key)
        if new_key.name:
            tuf_key.unrecognized_fields["name"] = new_key.name

        self._new_md.signed.add_key(tuf_key, Root.type)
        self.signing_keys[new_key.key["keyid"]] = new_key

    def change_online_key(self, new_online_key: RSTUFKey) -> None:
        """Replace the current online key with a new one."""
        # Remove the current online key
        online_key_id = self._new_md.signed.roles["timestamp"].keyids[0]
        # Top level roles that use the online key
        online_roles = ["timestamp", "snapshot", "targets"]
        for role in online_roles:
            self._new_md.signed.revoke_key(online_key_id, role)

        # Add the new online key
        online_tuf_key = Key.from_securesystemslib_key(new_online_key.key)
        if new_online_key.name:
            online_tuf_key.unrecognized_fields["name"] = new_online_key.name

        for role in online_roles:
            self._new_md.signed.add_key(online_tuf_key, role)

    def has_changed(self) -> bool:
        """Returns whether the root metadata object has changed"""
        return self._trusted_md != self._new_md

    def get_signer(self, key: RSTUFKey) -> Signer:
        return SSlibSigner(key.key)

    def generate_payload(self) -> Dict[str, Any]:
        """Save the root metadata into 'file'"""
        self._new_md.signed.version += 1
        self._new_md.signatures.clear()

        new_root_keyids = self._new_md.signed.roles["root"].keyids
        trusted_root_keyids = self._trusted_md.signed.roles["root"].keyids
        # Sign only with keys existing in the new root version or part from
        # previous trusted root. Threshold (threshold comes from trusted root)
        # number of keys from previous threshold must sign new root to achieve
        # chain of trust between root versions.
        for keyid, key in self.signing_keys.items():
            if keyid in new_root_keyids or keyid in trusted_root_keyids:
                self._new_md.sign(SSlibSigner(key.key), append=True)

        console.print("\nVerifying the new payload...")
        try:
            # Verify that the new root is signed by the trusted current root
            self._trusted_md.verify_delegate(Root.type, self._new_md)
        except UnsignedMetadataError:
            trusted_keys_amount = 0
            for keyid in self._trusted_md.signed.roles["root"].keyids:
                if keyid in self.signing_keys:
                    trusted_keys_amount += 1

            t = self._trusted_md.signed.roles["root"].threshold
            raise click.ClickException(
                "Not enough loaded keys left from current root: "
                f"needed {t}, have {trusted_keys_amount}"
            )

        # Verify that the new root is signed by at least threshold of keys
        self._new_md.verify_delegate(Root.type, self._new_md)
        console.print("The new payload is [green]verified[/]")

        return {"metadata": {"root": self._new_md.to_dict()}}


class TUFManagement:
    """
    Class responsible for all actions upon TUF metadata.
    """

    def __init__(self, setup: BootstrapSetup, save=True) -> None:
        self.setup = setup
        self.save = save
        self.repository_metadata: Dict[str, Metadata] = {}

    def _signers(self, role: Roles) -> List[Signer]:
        """Returns all Signers from the settings for a specific role name"""
        result: List[Signer] = []
        if role == Roles.ROOT:
            for key in self.setup.root_keys.values():
                # Make sure this key was loaded, not just described.
                if key.key["keyval"].get("private"):
                    result.append(SSlibSigner(key.key))

        return result

    def _public_keys(self, role: Roles) -> List[Dict[str, Any]]:
        """Get public keys for the role 'role'."""
        if role == Roles.ROOT:
            return [key.key for key in self.setup.root_keys.values()]
        else:
            return [self.setup.online_key.key]

    def _sign(self, role: Metadata, role_name: str) -> None:
        """Re-signs metadata with role-specific key from global key store.
        The metadata role type is used as default key id. This is only allowed
        for top-level roles.
        """
        role.signatures.clear()
        for signer in self._signers(Roles[role_name.upper()]):
            if signer.key_dict["keyval"].get("private") is not None:
                role.sign(signer, append=True)

    def _add_payload(self, role: Metadata, role_name: str) -> None:
        """Persists metadata using the configured storage backend.
        The metadata role type is used as default role name. This is only
        allowed for top-level roles. All names but 'timestamp' are prefixed
        with a version number.
        """
        self.repository_metadata[role_name] = role

        if self.save:
            ver = role.signed.version
            role.to_file(f"metadata/{ver}.{role_name}.json", JSONSerializer())

    def _bump_expiry(self, role: Metadata, role_name: str) -> None:
        """Bumps metadata expiration date by role-specific interval.
        The metadata role type is used as default expiry id. This is only
        allowed for top-level roles.
        """
        # FIXME: Review calls to _bump_expiry. Currently, it is called in
        # every update-sign-persist cycle.
        # PEP 458 is unspecific about when to bump expiration, e.g. in the
        # course of a consistent snapshot only 'timestamp' is bumped:
        # https://www.python.org/dev/peps/pep-0458/#producing-consistent-snapshots
        role.signed.expires = datetime.now().replace(
            microsecond=0
        ) + timedelta(days=self.setup.expiration[Roles[role_name.upper()]])

    def _validate_root_payload_exist(self):
        """
        Validate that root is initialized with a correct information.
        """
        try:
            root_md = self.repository_metadata[Roles.ROOT.value]
            if not isinstance(root_md, Metadata):
                raise ValueError()
        except (KeyError, ValueError) as err:
            raise ValueError("Root is not initialized") from err

    def _verify_correct_keys_usage(self, root: Root):
        """
        Verify that all top-level roles share the same online key except root.
        """
        # We consider the timestamp key as the online key to compare against
        timestamp_keyid: str = root.roles["timestamp"].keyids[0]
        for role in ["timestamp", "snapshot", "targets"]:
            if len(root.roles[role].keyids) != 1:
                raise ValueError(f"Expected exactly one online key for {role}")

            role_keyid = root.roles[role].keyids[0]
            if role_keyid != timestamp_keyid:
                raise ValueError(
                    f"{role} keyid must be equal to the one used in timestamp"
                )

        if timestamp_keyid in root.roles["root"].keyids:
            raise ValueError("Root must not use the same key as timestamp")

    def _prepare_root_and_add_it_to_payload(
        self, roles: dict[str, Role], add_key_args: Dict[str, List[Key]]
    ):
        """
        Prepare root metadata and add it to the payload.
        """
        # Add signature, bump expiration, sign and persist the root role.
        root_metadata = Metadata(Root(roles=roles))
        for role, keys in add_key_args.items():
            for key in keys:
                root_metadata.signed.add_key(key, role)

        self._verify_correct_keys_usage(root_metadata.signed)

        metadata_type = root_metadata.signed.type
        self._bump_expiry(root_metadata, metadata_type)
        self._sign(root_metadata, metadata_type)
        self._add_payload(root_metadata, metadata_type)

    def _setup_key_name(self, key: Key, role: str):
        rstuf_key: Optional[RSTUFKey]
        if role == Roles.ROOT.value:
            rstuf_key = self.setup.root_keys.get(key.keyid)

        else:
            if self.setup.online_key.key["keyid"] == key.keyid:
                rstuf_key = self.setup.online_key

        if rstuf_key is not None and rstuf_key.name is not None:
            key.unrecognized_fields["name"] = rstuf_key.name

    def initialize_metadata(self) -> Dict[str, Metadata]:
        """
        Creates TUF top-level role metadata (root, targets, snapshot and
        timestamp).
        """
        # Populate public key store, and define trusted signing keys and
        # required signature thresholds for each top-level role in 'root'.
        roles: dict[str, Role] = {}
        add_key_args: Dict[str, List[Key]] = {}
        for role_name in ["root", "timestamp", "snapshot", "targets"]:
            if role_name == Roles.ROOT.value:
                threshold = self.setup.threshold[Roles.ROOT]
            else:
                threshold = 1

            public_keys = self._public_keys(Roles[role_name.upper()])
            add_key_args[role_name] = []
            roles[role_name] = Role([], threshold)
            for securesystemslib_key in public_keys:
                key = Key.from_securesystemslib_key(securesystemslib_key)
                self._setup_key_name(key, role_name)
                add_key_args[role_name].append(key)

        self._prepare_root_and_add_it_to_payload(roles, add_key_args)
        self._validate_root_payload_exist()

        return self.repository_metadata


def get_supported_schemes_for_key_type(key_type: str) -> List[str]:
    supported_schemes: List[str] = []
    for info in KEY_FOR_TYPE_AND_SCHEME.keys():
        if info[0] == key_type:
            supported_schemes.append(info[1])

    return supported_schemes


def _conform_rsa_key(input_key: str) -> str:
    "Conform public key in base64 format to format used by securesystemslib."
    try:
        kms_pubkey = serialization.load_der_public_key(
            base64.b64decode(input_key)
        )
        public_key_pem = kms_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return public_key_pem
    except Exception:
        return input_key


def get_key(
    role: Optional[str] = None,
    key_type: str = "",
    ask_name: bool = False,
) -> RSTUFKey:
    role = f"{click.style(role, fg='cyan')}`s " if role is not None else ""
    if key_type == "":
        key_type = prompt.Prompt.ask(
            f"\nChoose {role}key type",
            choices=KeyType.get_all_members(),
            default=KeyType.KEY_TYPE_ED25519.value,
        )

    filepath: str = prompt.Prompt.ask(
        f"Enter the {role}private key [green]path[/]"
    )
    password_green = click.style("password", fg="green")
    password: str = click.prompt(
        f"Enter the {role}private key {password_green}", hide_input=True
    )
    name = ""
    if ask_name:
        name = prompt.Prompt.ask(
            f"[Optional] Give a [green]name/tag[/] to the {role}key",
            default="",
            show_default=False,
        )

    return load_key(filepath, key_type, password, name)


def load_key(path: str, keytype: str, password: str, name: str) -> RSTUFKey:
    """Load a securesystemslib private key file into an RSTUFKey object"""
    try:
        key = import_privatekey_from_file(path, keytype, password)
        # Make sure name cannot be an empty string.
        # If no name is given use first 7 letters of the keyid.
        name = name if name != "" else key["keyid"][:7]
        return RSTUFKey(key=key, key_path=path, name=name)
    except CryptoError as err:
        return RSTUFKey(
            error=(
                f":cross_mark: [red]Failed[/]: {str(err)} Check the"
                " password, type, etc"
            )
        )

    except (StorageError, FormatError, Error, OSError) as err:
        return RSTUFKey(error=f":cross_mark: [red]Failed[/]: {str(err)}")


def load_payload(path: str) -> Dict[str, Any]:
    """Load existing payload file."""
    try:
        with open(path) as payload_data:
            payload = json.load(payload_data)
    except OSError as err:
        raise click.ClickException(f"Error to load {path}. {str(err)}")

    return payload


def save_payload(file_path: str, payload: Dict[str, Any]):
    """Save the 'payload' into a file with path 'file_path'"""
    # Add .json extension if not there
    if not file_path.endswith(".json"):
        file_path += ".json"
    try:
        with open(file_path, "w") as f:
            f.write(json.dumps(payload, indent=2))
    except OSError as err:
        raise click.ClickException(f"Failed to save {file_path}. {str(err)}")


def print_key_table(rstuf_key: RSTUFKey) -> None:
    key_table = table.Table()
    key_table.add_column("Key ID", justify="center")
    key_table.add_column("Key Type", justify="center")
    key_table.add_column("Key Scheme", justify="center")
    key_table.add_column("Public Key", justify="center")
    row_items = [
        rstuf_key.key["keyid"],
        rstuf_key.key["keytype"],
        rstuf_key.key["scheme"],
        rstuf_key.key["keyval"]["public"],
    ]

    key_table.add_row(*row_items)
    console.print(key_table)
