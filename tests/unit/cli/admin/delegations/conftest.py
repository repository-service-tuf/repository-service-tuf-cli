# SPDX-FileCopyrightText: 2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

"""Trusted-metadata fixtures shared by the delegation command tests.

The repository modelled here is a small one: a single repository online key,
one delegation signed by it, one signed by offline keys, and one that nests
hash bins signed by a role-specific online key of its own.
"""

import copy
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from securesystemslib.signer import SSlibKey
from tuf.api.metadata import Delegations, DelegatedRole, Metadata, Targets

from repository_service_tuf.cli.admin.helpers import (
    KEY_NAME_FIELD,
    KEY_URI_FIELD,
    ROLE_ONLINE_KEY_FIELD,
)
from tests.conftest import _PEMS

# Public keys used below. The online-key file is named after its own keyid,
# which is why it reads as a hash.
REPOSITORY_KEY = (
    "0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub"
)
ROLE_ONLINE_KEY = "JC.pub"
OFFLINE_KEY_A = "JH.pub"
OFFLINE_KEY_B = "JJ.pub"


def load_public_key(
    filename: str, name: str, online: bool = False
) -> SSlibKey:
    """Load one of the test public keys as RSTUF would declare it."""
    with open(_PEMS / filename, "rb") as f:
        key = SSlibKey.from_crypto(load_pem_public_key(f.read()))

    key.unrecognized_fields[KEY_NAME_FIELD] = name
    if online:
        key.unrecognized_fields[KEY_URI_FIELD] = f"fn:{key.keyid}"

    return key


def key_path(filename: str) -> str:
    return str(_PEMS / filename)


def delegated_role(
    name: str,
    keyids: List[str],
    threshold: int = 1,
    num_bins: Optional[int] = None,
    role_online_keyid: Optional[str] = None,
) -> DelegatedRole:
    unrecognized_fields: Dict[str, object] = {"x-rstuf-expire-policy": 30}
    if num_bins is not None:
        unrecognized_fields["x-rstuf-num-bins"] = num_bins
    if role_online_keyid is not None:
        unrecognized_fields[ROLE_ONLINE_KEY_FIELD] = role_online_keyid

    return DelegatedRole(
        name=name,
        keyids=list(keyids),
        threshold=threshold,
        terminating=num_bins is None,
        paths=[f"{name}/*"],
        unrecognized_fields=unrecognized_fields,
    )


@pytest.fixture
def repository_key() -> SSlibKey:
    """The URI-tagged online key the repository declares in root."""
    return load_public_key(REPOSITORY_KEY, "online", online=True)


@pytest.fixture
def role_online_key() -> SSlibKey:
    """The online key signing the hash bins nested below `fastapi`."""
    return load_public_key(ROLE_ONLINE_KEY, "fastapi-bins", online=True)


@pytest.fixture
def offline_keys() -> Dict[str, SSlibKey]:
    return {
        key.keyid: key
        for key in (
            load_public_key(OFFLINE_KEY_A, "JH"),
            load_public_key(OFFLINE_KEY_B, "JJ"),
        )
    }


@pytest.fixture
def targets_md(
    repository_key, role_online_key, offline_keys
) -> Metadata[Targets]:
    """Targets with three delegations, as the Worker would have written it.

    `advisories` signs with the repository online key, `pytorch` with two
    offline keys, and `fastapi` nests hash bins signed by its own online key.
    Note that the Worker records the repository online key in a role's
    `keyids` even when the ceremony left them empty.
    """
    keys = {repository_key.keyid: copy.deepcopy(repository_key)}
    # The Worker declares a role's nested-bins key here too, so a delegation
    # update can re-send the key its role points at.
    keys[role_online_key.keyid] = copy.deepcopy(role_online_key)
    for keyid, key in offline_keys.items():
        keys[keyid] = copy.deepcopy(key)

    offline_a, offline_b = list(offline_keys)
    targets = Targets(expires=datetime.now(timezone.utc) + timedelta(days=365))
    targets.delegations = Delegations(
        keys=keys,
        roles={
            "advisories": delegated_role(
                "advisories", [repository_key.keyid]
            ),
            "pytorch": delegated_role(
                "pytorch", [offline_a, offline_b], threshold=2
            ),
            "fastapi": delegated_role(
                "fastapi",
                [repository_key.keyid],
                num_bins=16,
                role_online_keyid=role_online_key.keyid,
            ),
        },
    )

    return Metadata(targets)
