# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Literal, Optional

from securesystemslib.signer import Signer, SSlibSigner  # type: ignore
from tuf.api.metadata import SPECIFICATION_VERSION, Key, Metadata, Role, Root
from tuf.api.serialization.json import JSONSerializer

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
    error: Optional[str] = None


@dataclass
class BootstrapSetup:
    expiration: Dict[Roles, int]
    services: ServiceSettings
    number_of_keys: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    threshold: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    root_keys: List[RSTUFKey] = field(default_factory=list)
    online_key: RSTUFKey = field(default_factory=RSTUFKey)

    def to_dict(self):
        return {
            "expiration": {k.value: v for k, v in self.expiration.items()},
            "services": self.services.to_dict(),
        }


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
            return [SSlibSigner(key.key) for key in self.setup.root_keys]
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
                add_key_args[role_name].append(
                    Key.from_securesystemslib_key(signer.key_dict)
                )

        self._prepare_root_and_add_it_to_payload(roles, add_key_args)
        self._validate_root_payload_exist()

        return self.repository_metadata
