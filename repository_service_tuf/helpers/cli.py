# SPDX-License-Identifier: MIT

import hashlib
import os
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class PayloadTargetsHashes(str, Enum):
    """The supported hashes of `TargetsInfo`"""

    # TODO: Update if needed after https://github.com/repository-service-tuf/repository-service-tuf-api/issues/379  # noqa: E501

    blake2b_256 = "blake2b-256"


@dataclass
class TargetsInfo:
    """The target information of `Targets`"""

    # An integer length in bytes
    # https://theupdateframework.github.io/specification/latest/#metapath-length
    length: int
    hashes: Dict[PayloadTargetsHashes, str]
    custom: Optional[Dict[str, Any]]


@dataclass
class Targets:
    """A target of `AddPayload`"""

    info: TargetsInfo
    path: str


@dataclass
class AddPayload:
    """The `POST /api/v1/artifacts/` required payload."""

    targets: List[Targets]
    # Whether to add the id of the task in custom
    add_task_id_to_custom: bool = False
    # Whether to publish the targets
    publish_targets: bool = True

    def to_dict(self):
        return asdict(self)


def calculate_blake2b_256(filepath: str) -> str:
    """
    Calculate the blake2b-256 hash of the given file.

    :param filepath: The path to the file for which we want to calculate the
    hash.
    """

    # Using non-default digest size of 32 for blake2b-256
    hasher = hashlib.blake2b(digest_size=32)

    # 8kB chunk size
    chunk_size_bytes = 8 * 1024

    with open(filepath, "rb") as file:
        # We calculate the hash of the file in chunks as to not load it all
        # at once in memory.
        for chunk in iter(lambda: file.read(chunk_size_bytes), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def create_artifact_payload_from_filepath(
    filepath: str, path: str
) -> Dict[str, Any]:
    """
    Create the payload for the API request of `POST api/v1/artifacts/`.

    The blake2b-256 cryptographic hash function is used to hash the file.

    :param filepath: The path to the file to be added as an artifact to the
    metadata.
    :param path: The path defined in the metadata for the target.
    """

    length: int = os.path.getsize(filepath)
    blake2b_256_hash: str = calculate_blake2b_256(filepath)

    payload = AddPayload(
        targets=[
            Targets(
                info=TargetsInfo(
                    length=length,
                    hashes={
                        PayloadTargetsHashes.blake2b_256: blake2b_256_hash
                    },
                    custom=None,
                ),
                path=f"{path.rstrip('/')}/{filepath.split('/')[-1]}",
            )
        ]
    )

    return payload.to_dict()
