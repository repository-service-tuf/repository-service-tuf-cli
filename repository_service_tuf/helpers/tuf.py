# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from securesystemslib.signer import Signer, SSlibSigner  # type: ignore
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
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
BIN: str = "bin"
BINS: str = "bins"


repository_metadata: Dict[str, Metadata] = {}


@dataclass
class KeySchema:
    # "key": Any (Any follows the ED25519KEY_SCHEMA from securesystemslib)
    key: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class KeyInput:
    filepath: str
    password: str
    key: KeySchema

    def to_dict(self):
        return asdict(self)


@dataclass
class RoleSettingsInput:
    expiration: int = 1
    num_of_keys: int = 1
    threshold: int = 1
    keys: Dict[str, KeyInput] = None
    offline_keys: bool = True
    paths: Optional[List[str]] = None
    number_hash_prefixes: Optional[int] = None

    def to_dict(self):
        return asdict(self)


def initialize_metadata(
    settings: Dict[str, RoleSettingsInput], save=True
) -> Dict[str, Metadata]:
    """
    Creates development TUF top-level role metadata (root, targets, snapshot,
    timestamp).
    """

    def _load(role_name: str) -> Metadata:
        """
        Loads latest version of metadata for rolename from metadata_repository
        dict
        """
        if role_name == Timestamp.type:
            filename = f"{role_name}"
        else:
            filenames = [
                filename
                for filename in repository_metadata
                if role_name in filename
            ]
            versions = [
                int(name.split("/")[-1].split(".", 1)[0]) for name in filenames
            ]
            try:
                version = max(versions)
            except ValueError:
                version = 1

            filename = f"{version}.{role_name}"

        return repository_metadata[filename]

    def _signers(role_name: str) -> List[Signer]:
        """Returns all Signers from the settings for a specific role name"""
        return [
            SSlibSigner(key_input.key.key)
            for key_input in settings[role_name].keys.values()
        ]

    def _sign(role: Metadata, role_name: str) -> None:
        """Re-signs metadata with role-specific key from global key store.
        The metadata role type is used as default key id. This is only allowed
        for top-level roles.
        """
        role.signatures.clear()
        for signer in _signers(role_name):
            role.sign(signer, append=True)

    def _add_payload(role: Metadata, role_name: str) -> None:
        """Persists metadata using the configured storage backend.
        The metadata role type is used as default role name. This is only
        allowed for top-level roles. All names but 'timestamp' are prefixed
        with a version number.
        """
        filename = f"{role_name}"

        if role_name != Timestamp.type:
            filename = f"{role.signed.version}.{filename}"

        repository_metadata[filename] = role

        if save:
            role.to_file(f"metadata/{filename}", JSONSerializer())

    def _bump_expiry(role: Metadata, expiry_id: str) -> None:
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
        ) + timedelta(days=settings[expiry_id].expiration)

    def _bump_version(role: Metadata) -> None:
        """Bumps metadata version by 1."""
        role.signed.version += 1

    def _update_timestamp(snapshot_version: int):
        """Loads 'timestamp', updates meta info about passed 'snapshot'
        metadata, bumps version and expiration, signs and persists."""
        timestamp = _load(Timestamp.type)
        timestamp.signed.snapshot_meta = MetaFile(version=snapshot_version)

        _bump_version(timestamp)
        _bump_expiry(timestamp, Timestamp.type)
        _sign(timestamp, Timestamp.type)
        _add_payload(timestamp, Timestamp.type)

    def _update_snapshot(
        targets_meta: List[Tuple[str, int]]
    ) -> Metadata[Snapshot]:
        """Loads 'snapshot', updates meta info about passed 'targets'
        metadata, bumps version and expiration, signs and persists. Returns
        new snapshot version, e.g. to update 'timestamp'."""
        snapshot = _load(Snapshot.type)

        for name, version in targets_meta:
            snapshot.signed.meta[f"{name}.json"] = MetaFile(version=version)

        _bump_expiry(snapshot, Snapshot.type)
        _bump_version(snapshot)
        _sign(snapshot, Snapshot.type)
        _add_payload(snapshot, Snapshot.type)

        return snapshot.signed.version

    # Bootstrap default top-level metadata to be updated below if necessary
    targets = Targets()
    snapshot = Snapshot()
    timestamp = Timestamp()
    root = Root()

    # Populate public key store, and define trusted signing keys and required
    # signature thresholds for each top-level role in 'root'.
    for role_name in TOP_LEVEL_ROLE_NAMES:
        threshold = settings[role_name].threshold
        signers = _signers(role_name)

        # FIXME: Is this a meaningful check? Should we check more than just
        # the threshold? And maybe in a different place, e.g. independently of
        # bootstrapping the metadata, because in production we do not have
        # access to all top-level role signing keys at the time of
        # bootstrapping the metadata.
        assert len(signers) >= threshold, (
            f"not enough keys ({len(signers)}) for "
            f"signing threshold '{threshold}'"
        )

        root.roles[role_name] = Role([], threshold)
        for signer in signers:
            root.add_key(
                Key.from_securesystemslib_key(signer.key_dict), role_name
            )

    # Add signature wrapper, bump expiration, and sign and persist
    for role in [targets, snapshot, timestamp, root]:
        metadata = Metadata(role)
        _bump_expiry(metadata, role.type)
        _sign(metadata, role.type)
        _add_payload(metadata, role.type)

    # Track names and versions of new and updated targets for 'snapshot'
    # update
    targets_meta = []

    # Update top-level 'targets' role, to delegate trust for all target files
    # to 'bins' role, defining target path patterns, trusted signing keys and
    # required signature thresholds.
    targets = _load(Targets.type)
    targets.signed.delegations = Delegations(keys={}, roles={})
    targets.signed.delegations.roles[BIN] = DelegatedRole(
        name=BIN,
        keyids=[],
        threshold=settings[BIN].threshold,
        terminating=False,
        paths=settings[Targets.type].paths,
    )

    for signer in _signers(BIN):
        targets.signed.add_key(
            Key.from_securesystemslib_key(signer.key_dict), BIN
        )

    # Bump version and expiration, and sign and persist updated 'targets'.
    _bump_version(targets)
    _bump_expiry(targets, Targets.type)
    _sign(targets, Targets.type)
    _add_payload(targets, Targets.type)

    targets_meta.append((Targets.type, targets.signed.version))

    succinct_roles = SuccinctRoles(
        [], 1, settings[BINS].number_hash_prefixes, BINS
    )
    # Create new 'bins' role and delegate trust from 'bins' for all target
    # files to 'bin-n' roles based on file path hash prefixes, a.k.a hash bin
    # delegation.
    bin = Metadata(Targets())
    bin.signed.delegations = Delegations(
        keys={}, succinct_roles=succinct_roles
    )
    for delegated_name in succinct_roles.get_roles():
        for signer in _signers(BINS):
            bin.signed.add_key(
                Key.from_securesystemslib_key(signer.key_dict), delegated_name
            )
        bins_hash_role = Metadata(Targets())
        _bump_expiry(bins_hash_role, BINS)
        _sign(bins_hash_role, BINS)
        _add_payload(bins_hash_role, delegated_name)
        targets_meta.append((delegated_name, bins_hash_role.signed.version))

    # Bump expiration, and sign and persist new 'bins' role.
    _bump_expiry(bin, BIN)
    _sign(bin, BIN)
    _add_payload(bin, BIN)

    targets_meta.append((BIN, bin.signed.version))

    _update_timestamp(_update_snapshot(targets_meta))

    return repository_metadata
