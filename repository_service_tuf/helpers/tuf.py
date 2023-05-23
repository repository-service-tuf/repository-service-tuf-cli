# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import copy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from securesystemslib.signer import Signer, SSlibSigner  # type: ignore
from tuf.api.metadata import SPECIFICATION_VERSION, Key, Metadata, Role, Root
from tuf.api.serialization.json import JSONSerializer

from rich.console import Console

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
class ServiceSettings:
    number_of_delegated_bins: int = 256
    targets_base_url: str = ""
    targets_online_key: bool = True

    def to_dict(self):
        return asdict(self)


@dataclass
class RSTUFKey:
    key: dict = field(default_factory=dict)
    key_path: Optional[str] = None
    name: Optional[str] = None
    error: Optional[str] = None

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, RSTUFKey):
            return False

        return self.key["keyid"] == other.key["keyid"]


@dataclass
class BootstrapSetup:
    expiration: Dict[Roles, int]
    services: ServiceSettings
    number_of_keys: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    threshold: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    root_keys: Dict[str, RSTUFKey] = field(default_factory=Dict)
    online_key: RSTUFKey = field(default_factory=RSTUFKey)

    def to_dict(self):
        return {
            "expiration": {k.value: v for k, v in self.expiration.items()},
            "services": self.services.to_dict(),
        }


class RootInfo:
    _root_md: Metadata[Root]
    root_keys: Dict[str, RSTUFKey]  # key are the root "names"
    _current_root_signing_keys: List[RSTUFKey]  # required for signing
    online_key: RSTUFKey
    _initial_root_md_obj: Metadata[
        Root
    ]  # required to check if root is changed

    @property
    def threshold(self) -> int:
        return self._root_md.signed.roles[Root.type].threshold

    @threshold.setter
    def threshold(self, value: int) -> None:
        self._root_md.signed.roles[Root.type].threshold = value

    @property
    def expiration(self) -> datetime:
        return self._root_md.signed.expires

    @expiration.setter
    def expiration(self, value: datetime) -> None:
        self._root_md.signed.expires = value

    @property
    def expiration_str(self) -> str:
        return f"{self.expiration.strftime('%Y-%b-%d')}"

    def __init__(
        self,
        root_md: Metadata[Root],
        root_keys: Dict[str, RSTUFKey],
        online_key: RSTUFKey,
    ):
        self._root_md = root_md
        self.root_keys = root_keys
        self.online_key = online_key
        self._current_root_signing_keys = []
        self._initial_root_md_obj = copy.deepcopy(self._root_md)

    @classmethod
    def _get_name(cls, key: Union[Key, RSTUFKey]) -> str:
        name: str
        if isinstance(key, Key):
            name = key.keyid[:7]
            if key.unrecognized_fields.get("name") is not None:
                name = key.unrecognized_fields["name"]

        elif isinstance(key, RSTUFKey):
            if key.name is None or key.name == "":
                name = key.key["keyid"][:7]
            else:
                name = key.name

        return name

    @classmethod
    def from_md(cls, root_md: Metadata[Root]) -> "RootInfo":
        root_keys: Dict[str, RSTUFKey] = {}
        for keyid in root_md.signed.roles[Root.type].keyids:
            tuf_key: Key = root_md.signed.keys[keyid]
            name = cls._get_name(tuf_key)
            tuf_key.unrecognized_fields["name"] = name
            key_dict = tuf_key.to_securesystemslib_key()
            root_keys[name] = RSTUFKey(key_dict, name=name)

        online_key_id = root_md.signed.roles["timestamp"].keyids[0]
        tuf_online_key: Key = root_md.signed.keys[online_key_id]
        online_key_dict = tuf_online_key.to_securesystemslib_key()
        name = cls._get_name(tuf_online_key)
        online_key = RSTUFKey(online_key_dict, name=name)

        return cls(root_md, root_keys, online_key)

    def is_keyid_used(self, keyid: str) -> bool:
        """Check if keyid is used in root keys"""
        if keyid not in self._root_md.signed.roles[Root.type].keyids:
            return False

        return True

    def save_current_root_key(self, key: RSTUFKey):
        """Update internal information based on 'key' data."""
        tuf_key: Key = self._root_md.signed.keys[key.key["keyid"]]
        if isinstance(tuf_key.unrecognized_fields.get("name"), str):
            key.name = tuf_key.unrecognized_fields["name"]

        key.name = self._get_name(tuf_key)
        self.root_keys[key.name] = key
        self._current_root_signing_keys.append(key)

    def remove_key(self, key_name: str) -> bool:
        """Try to remove a key and return status of the operation"""
        key = self.root_keys.get(key_name)
        if key is None:
            return False

        self._root_md.signed.revoke_key(key.key["keyid"], Root.type)
        self.root_keys.pop(key_name)
        return True

    def add_key(self, new_key: RSTUFKey) -> None:
        """Add a new key."""
        name = RootInfo._get_name(new_key)
        new_key.name = name
        tuf_key = Key.from_securesystemslib_key(new_key.key)
        tuf_key.unrecognized_fields["name"] = name
        self._root_md.signed.add_key(tuf_key, Root.type)

        self.root_keys[name] = new_key

    def change_online_key(self, new_online_key: RSTUFKey):
        """Replace the old online key with a new one."""
        # Remove the old online key
        online_key_id = self._root_md.signed.roles["timestamp"].keyids[0]
        # Top level roles that use the online key
        online_roles = ["timestamp", "snapshot", "targets"]
        for role in online_roles:
            self._root_md.signed.revoke_key(online_key_id, role)

        # Add the new online key
        name = RootInfo._get_name(new_online_key)
        new_online_key.name = name
        online_tuf_key = Key.from_securesystemslib_key(new_online_key.key)
        online_tuf_key.unrecognized_fields["name"] = name
        for role in online_roles:
            self._root_md.signed.add_key(online_tuf_key, role)

        self.online_key = new_online_key

    def has_changed(self) -> bool:
        """Returns whether the root metadata object has changed"""
        if self._initial_root_md_obj != self._root_md:
            return True
        else:
            return False

    def generate_payload(self) -> Dict[str, Any]:
        """Save the root metadata into 'file'"""
        self._root_md.signed.version += 1
        self._root_md.signatures.clear()

        # As the spec says: sign the new root with threshold amount of current
        # root keys where "threshold" comes from the current root. See:
        # https://theupdateframework.github.io/specification/latest/#key-management-and-migration
        for curr_root_key in self._current_root_signing_keys:
            self._root_md.sign(SSlibSigner(curr_root_key.key), append=True)

        # Then sign the new root with the rest of the keys
        for key in self.root_keys.values():
            # Make sure we don't sign with the same key twice.
            already_used_key = False
            for curr_root_key in self._current_root_signing_keys:
                if key.key["keyid"] == curr_root_key.key["keyid"]:
                    already_used_key = True
                    break

            if already_used_key:
                continue

            # If key.key_path is None this means this key was not loaded by the
            # user and doesn't have the data required to sign the metadata.
            if key.key_path is None:
                continue

            self._root_md.sign(SSlibSigner(key.key), append=True)

        console.print("\nVerifying the new payload...")
        self._root_md.verify_delegate(Root.type, self._root_md)
        console.print("The new payload is [green]verified[/]")

        return {"metadata": {"root": self._root_md.to_dict()}}


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
        if role == Roles.ROOT:
            return [
                SSlibSigner(key.key) for key in self.setup.root_keys.values()
            ]
        else:
            return [SSlibSigner(self.setup.online_key.key)]

    def _sign(self, role: Metadata, role_name: str) -> None:
        """Re-signs metadata with role-specific key from global key store.
        The metadata role type is used as default key id. This is only allowed
        for top-level roles.
        """
        role.signatures.clear()
        for signer in self._signers(Roles[role_name.upper()]):
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

            signers = self._signers(Roles[role_name.upper()])

            # FIXME: Is this a meaningful check? Should we check more than just
            # the threshold? And maybe in a different place, e.g. independently
            # of bootstrapping the metadata, because in production we do not
            # have access to all top-level role signing keys at the time of
            # bootstrapping the metadata.
            if len(signers) < threshold:
                raise ValueError(
                    f"not enough keys ({len(signers)}) for "
                    f"signing threshold '{threshold}'"
                )
            add_key_args[role_name] = []
            roles[role_name] = Role([], threshold)
            for signer in signers:
                key = Key.from_securesystemslib_key(signer.key_dict)
                self._setup_key_name(key, role_name)
                add_key_args[role_name].append(key)

        self._prepare_root_and_add_it_to_payload(roles, add_key_args)
        self._validate_root_payload_exist()

        return self.repository_metadata
