# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from math import log
from typing import Dict, List, Literal, Optional, Tuple

from securesystemslib.signer import Signer, SSlibSigner  # type: ignore
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    SuccinctRoles,
    Targets,
    Timestamp,
)
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
    # Before key was optional. Not sure why.
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

    def _load(self, role_name: str) -> Metadata:
        """
        Loads latest version of metadata for rolename from metadata_repository
        dict
        """
        if role_name == Timestamp.type:
            filename = f"{role_name}"

            if filename not in self.repository_metadata:
                raise ValueError("Timestamp is not initialized")
        else:
            filenames = [
                filename
                for filename in self.repository_metadata
                if role_name in filename
            ]

            if len(filenames) < 1:
                raise ValueError(f"No filename found for {role_name}")

            versions = [
                int(name.split("/")[-1].split(".", 1)[0]) for name in filenames
            ]

            version = max(versions)

            if version < 1:
                raise ValueError("Metadata version must be at least 1")

            filename = f"{version}.{role_name}"

        return self.repository_metadata[filename]

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
        filename = role_name

        if role_name != Timestamp.type:
            filename = f"{role.signed.version}.{filename}"

        self.repository_metadata[filename] = role

        if self.save:
            role.to_file(f"metadata/{filename}.json", JSONSerializer())

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

    def _bump_version(self, role: Metadata) -> None:
        """Bumps metadata version by 1."""
        role.signed.version += 1

    def _update_timestamp(self, snapshot_version: int):
        """Loads 'timestamp', updates meta info about passed 'snapshot'
        metadata, bumps version and expiration, signs and persists."""
        timestamp = self._load(Timestamp.type)
        timestamp.signed.snapshot_meta = MetaFile(version=snapshot_version)

        self._bump_version(timestamp)
        self._bump_expiry(timestamp, Timestamp.type)
        self._sign(timestamp, Timestamp.type)
        self._add_payload(timestamp, Timestamp.type)

    def _update_snapshot(self, targets_meta: List[Tuple[str, int]]) -> int:
        """Loads 'snapshot', updates meta info about passed 'targets'
        metadata, bumps version and expiration, signs and persists. Returns
        new snapshot version, e.g. to update 'timestamp'."""
        snapshot = self._load(Snapshot.type)

        for name, version in targets_meta:
            snapshot.signed.meta[f"{name}.json"] = MetaFile(version=version)

        self._bump_expiry(snapshot, Snapshot.type)
        self._bump_version(snapshot)
        self._sign(snapshot, Snapshot.type)
        self._add_payload(snapshot, Snapshot.type)

        return snapshot.signed.version

    def initialize_metadata(self) -> Dict[str, Metadata]:
        """
        Creates development TUF top-level role metadata (root, targets,
        snapshot and timestamp).
        """
        # Populate public key store, and define trusted signing keys and
        # required signature thresholds for each top-level role in 'root'.
        roles: dict[str, Role] = {}
        add_key_args: list[tuple[Key, str]] = []
        for role_name in TOP_LEVEL_ROLE_NAMES:
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

            roles[role_name] = Role([], threshold)
            for signer in signers:
                add_key_args.append(
                    (Key.from_securesystemslib_key(signer.key_dict), role_name)
                )

        # Add signature wrapper, bump expiration, and sign and persist
        for role in [Targets, Snapshot, Timestamp, Root]:
            # Bootstrap default top-level metadata to be updated below if
            # necessary.
            if role is Root:
                metadata = Metadata(Root(roles=roles))
                root = metadata.signed
                for arg in add_key_args:
                    root.add_key(arg[0], arg[1])

            else:
                metadata = Metadata(role())

            metadata_type = metadata.signed.type
            self._bump_expiry(metadata, metadata_type)
            self._sign(metadata, metadata_type)
            self._add_payload(metadata, metadata_type)

        # Track names and versions of new and updated targets for 'snapshot'
        # update
        targets_meta = []

        # Update top-level 'targets' role, to delegate trust for all target
        # files to 'bin-n' roles based on file path hash prefixes, a.k.a hash
        # bin delegation.
        targets = self._load(Targets.type)
        succinct_roles = SuccinctRoles(
            [],
            1,
            int(log(self.setup.services.number_of_delegated_bins, 2)),
            BINS,
        )

        targets.signed.delegations = Delegations(
            keys={}, succinct_roles=succinct_roles
        )

        for delegated_name in succinct_roles.get_roles():
            for signer in self._signers(Roles.BINS):
                targets.signed.add_key(
                    Key.from_securesystemslib_key(signer.key_dict),
                    delegated_name,
                )
            bins_hash_role = Metadata(Targets())
            self._bump_expiry(bins_hash_role, BINS)
            self._sign(bins_hash_role, BINS)
            self._add_payload(bins_hash_role, delegated_name)
            targets_meta.append(
                (delegated_name, bins_hash_role.signed.version)
            )

        # Bump version and expiration, and sign and persist updated 'targets'.
        self._bump_version(targets)
        self._bump_expiry(targets, Targets.type)
        self._sign(targets, Targets.type)
        self._add_payload(targets, Targets.type)

        targets_meta.append((Targets.type, targets.signed.version))

        self._update_timestamp(self._update_snapshot(targets_meta))

        return self.repository_metadata
