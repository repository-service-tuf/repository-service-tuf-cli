# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from enum import Enum
from typing import Dict, List

from securesystemslib.interface import (  # type: ignore
    KEY_TYPE_ECDSA,
    KEY_TYPE_ED25519,
    KEY_TYPE_RSA,
)


class KeyType(str, Enum):
    """Represents the key types from `securesystemslib` that we support"""

    KEY_TYPE_ED25519 = KEY_TYPE_ED25519
    KEY_TYPE_ECDSA = KEY_TYPE_ECDSA
    KEY_TYPE_RSA = KEY_TYPE_RSA

    @classmethod
    def get_all_members(cls) -> List[str]:
        return [e.value for e in cls]


# Those defaults are taken from scheme arg default at
# import_KEY_TYPE_privatekey_from_file() functions at
# securesystemslib.interface.py
SCHEME_DEFAULTS: Dict[str, str] = {
    KeyType.KEY_TYPE_ED25519.value: KEY_TYPE_ED25519,
    KeyType.KEY_TYPE_ECDSA.value: "ecdsa-sha2-nistp256",
    KeyType.KEY_TYPE_RSA.value: "rsassa-pss-sha256",
}
