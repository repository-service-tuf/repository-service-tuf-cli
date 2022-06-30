# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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
    Targets,
    Timestamp,
)

from kaprien.helpers.hash_bins import HashBins

SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)
BIN: str = "bin"
BINS: str = "bins"


@dataclass
class RolesKeysInput:
    expiration: int = 1
    num_of_keys: int = 1
    threshold: int = 1
    keys: Dict[str, Any] = field(default_factory=dict)
    offline_keys: bool = True
    paths: Optional[List[str]] = None
    number_hash_prefixes: Optional[int] = None

    def to_dict(self):
        return asdict(self)


def initialize_metadata(
    settings: Dict[str, RolesKeysInput]
) -> Dict[str, Metadata]:
    def _role_expire(role_name: str) -> datetime:
        """Get role expire date calculated

        Args:
            role_name: Role name

        Return: datetime expire date
        """
        return datetime.now().replace(microsecond=0) + timedelta(
            days=settings[role_name].expiration
        )

    # creates the base TUF Metadata
    metadata: Dict[str, Metadata] = dict()
    signers: Dict[str, Signer] = dict()
    for rolename, details in settings.items():
        signers[rolename] = [
            SSlibSigner(keys["key"]) for keys in details.keys.values()
        ]

    targets = Targets(1, SPEC_VERSION, _role_expire(Targets.type), {}, None)
    metadata[Targets.type] = Metadata(targets, {})

    meta = {"targets.json": MetaFile(targets.version)}
    snapshot = Snapshot(1, SPEC_VERSION, _role_expire(Snapshot.type), meta)
    metadata[Snapshot.type] = Metadata(snapshot, {})

    snapshot_meta = MetaFile(snapshot.version)
    timestamp = Timestamp(
        1,
        SPEC_VERSION,
        _role_expire(Timestamp.type),
        snapshot_meta,
    )
    metadata[Timestamp.type] = Metadata(timestamp, {})

    roles = {
        role_name: Role([], settings[role_name].threshold)
        for role_name in TOP_LEVEL_ROLE_NAMES
    }
    root = Root(1, SPEC_VERSION, _role_expire(Root.type), {}, roles, True)
    metadata[Root.type] = Metadata(root, {})

    # sign all top level roles metadata
    for role in TOP_LEVEL_ROLE_NAMES:
        if settings[role].threshold > len(signers[role]):
            raise ValueError(
                f"Role {role} has missing Key(s) "
                f"to match to defined threshold "
                f"{settings[f'tuf.{role}.threshold']}."
            )

        for signer in signers[role]:
            root.add_key(role, Key.from_securesystemslib_key(signer.key_dict))
            metadata[role].sign(signer, append=True)

    # create the delegations
    # 1. Targets -> BIN
    metadata["2." + Targets.type] = deepcopy(metadata[Targets.type])
    metadata["2." + Snapshot.type] = deepcopy(metadata[Snapshot.type])
    metadata[BIN] = Metadata(
        Targets(1, SPEC_VERSION, _role_expire(BIN), {}, None), {}
    )
    delegated_bin = DelegatedRole(
        name=BIN,
        keyids=[signer.key_dict["keyid"] for signer in signers[BIN]],
        threshold=settings[BIN].threshold,
        terminating=False,
        paths=settings[Targets.type].paths,
    )

    metadata["2." + Targets.type].signed.delegations = Delegations(
        {
            signer.key_dict["keyid"]: Key.from_securesystemslib_key(
                signer.key_dict
            )
            for signer in signers[BIN]
        },
        {BIN: delegated_bin},
    )
    for signer in signers[BIN]:
        metadata["2." + Targets.type].signed.add_key(
            BIN, Key.from_securesystemslib_key(signer.key_dict)
        )
        metadata[BIN].sign(signer, append=True)

    metadata["2." + Targets.type].signed.version += 1
    metadata["2." + Targets.type].signed.expires = _role_expire(Targets.type)
    for signer in signers[Targets.type]:
        metadata["2." + Targets.type].sign(signer, append=True)

    metadata["2." + Snapshot.type].signed.meta[f"{BIN}.json"] = MetaFile(
        version=metadata[BIN].signed.version
    )
    metadata["2." + Snapshot.type].signed.meta[
        f"{Targets.type}.json"
    ] = MetaFile(version=metadata["2." + Targets.type].signed.version)
    metadata["2." + Snapshot.type].signed.version += 1
    metadata["2." + Snapshot.type].signed.expires = _role_expire(Snapshot.type)
    for signer in signers[Snapshot.type]:
        metadata["2." + Snapshot.type].sign(signer, append=True)

    # 2. BIN -> BINS (Hash Bins)
    num_prefixes: int = settings[BINS].number_hash_prefixes  # type: ignore
    hash_bins = HashBins(num_prefixes)

    metadata["2." + BIN] = deepcopy(metadata[BIN])
    metadata["3." + Snapshot.type] = deepcopy(metadata["2." + Snapshot.type])

    for bin_n_name, bin_n_hash_prefixes in hash_bins.generate():
        metadata[bin_n_name] = Metadata(
            Targets(1, SPEC_VERSION, _role_expire(BIN), {}, None), {}
        )
        delegated_bins = DelegatedRole(
            bin_n_name,
            [signer.key_dict["keyid"] for signer in signers[BINS]],
            settings[BINS].threshold,
            False,
            path_hash_prefixes=bin_n_hash_prefixes,
        )

        if metadata["2." + BIN].signed.delegations is None:
            metadata["2." + BIN].signed.delegations = Delegations(
                {
                    signer.key_dict["keyid"]: Key.from_securesystemslib_key(
                        signer.key_dict
                    )
                    for signer in signers[BINS]
                },
                {bin_n_name: delegated_bins},
            )

        else:
            metadata["2." + BIN].signed.delegations.roles[
                bin_n_name
            ] = delegated_bins

        for signer in signers[BINS]:
            metadata["2." + BIN].signed.add_key(
                bin_n_name, Key.from_securesystemslib_key(signer.key_dict)
            )
            metadata[bin_n_name].sign(signer, append=True)

        metadata["3." + Snapshot.type].signed.meta[
            f"{bin_n_name}.json"
        ] = MetaFile(version=metadata[bin_n_name].signed.version)

    metadata["2." + BIN].signed.version += 1
    metadata["2." + BIN].signed.expires = _role_expire(Targets.type)
    for signer in signers[BIN]:
        metadata["2." + BIN].sign(signer, append=True)

    metadata["3." + Snapshot.type].signed.version += 1
    metadata["3." + Snapshot.type].signed.expires = _role_expire(Snapshot.type)
    metadata["3." + Snapshot.type].signed.meta[f"{BIN}.json"] = MetaFile(
        version=metadata["2." + BIN].signed.version
    )
    for signer in signers[Snapshot.type]:
        metadata["3." + Snapshot.type].sign(signer, append=True)

    signers.clear()

    return metadata
