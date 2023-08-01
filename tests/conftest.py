# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from datetime import datetime
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Tuple

import pytest  # type: ignore
from click.testing import CliRunner  # type: ignore
from dynaconf import Dynaconf
from securesystemslib.signer import SSlibKey as Key
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.helpers.tuf import (
    BootstrapSetup,
    Roles,
    RootInfo,
    RSTUFKey,
    ServiceSettings,
    TUFManagement,
)


@pytest.fixture
def test_context() -> Dict[str, Any]:
    setting_file = os.path.join(TemporaryDirectory().name, "test_settings.ini")
    test_settings = Dynaconf(settings_files=[setting_file])
    test_settings.AUTH = False
    return {"settings": test_settings, "config": setting_file}


@pytest.fixture
def client() -> CliRunner:
    runner = CliRunner()
    return runner


@pytest.fixture
def test_setup() -> BootstrapSetup:
    setup = BootstrapSetup(
        expiration={
            Roles.ROOT: 365,
            Roles.TARGETS: 365,
            Roles.SNAPSHOT: 1,
            Roles.TIMESTAMP: 1,
            Roles.BINS: 1,
        },
        services=ServiceSettings(),
        number_of_keys={Roles.ROOT: 2, Roles.TARGETS: 1},
        threshold={
            Roles.ROOT: 1,
            Roles.TARGETS: 1,
        },
        root_keys={},
        online_key=RSTUFKey(),
    )

    return setup


@pytest.fixture
def test_tuf_management(test_setup: BootstrapSetup) -> TUFManagement:
    return TUFManagement(test_setup, False)


@pytest.fixture
def test_inputs() -> Tuple[List[str], List[str], List[str], List[str]]:
    input_step1 = [
        "y",  # Do you want more information about roles and responsibilities?  # noqa
        "y",  # Do you want to start the ceremony?
        "",  # What is the metadata expiration for the root role?(Days)
        "",  # What is the number of keys for the root role? (2)
        "",  # What is the key threshold for root role signing?
        "",  # What is the metadata expiration for the targets role?(Days) (365)?  # noqa
        "y",  # Show example?
        "16",  # Choose the number of delegated hash bin roles
        "http://www.example.com/repository",  # What is the targets base URL
        "",  # What is the metadata expiration for the snapshot role?(Days) (365)?  # noqa
        "",  # What is the metadata expiration for the timestamp role?(Days) (365)?  # noqa
        "",  # What is the metadata expiration for the bins role?(Days) (365)?
        "Y",  # Ready to start loading the keys? Passwords will be required for keys [y/n]  # noqa
    ]
    input_step2 = [
        "",  # Choose 1/1 ONLINE key type [ed25519/ecdsa/rsa]
        "tests/files/key_storage/online.key",  # Enter 1/1 the ONLINE`s private key path  # noqa
        "strongPass",  # Enter 1/1 the ONLINE`s private key password,
        "",  # [Optional] Give a name/tag to the key:
    ]
    input_step3 = [
        "",  # Choose 1/2 root key type [ed25519/ecdsa/rsa]
        "tests/files/key_storage/JanisJoplin.key",  # Enter 1/2 the root`s private key path  # noqa
        "strongPass",  # Enter 1/2 the root`s private key password
        "",  # [Optional] Give a name/tag to the key:
        "",  # Choose 2/2 root key type [ed25519/ecdsa/rsa]
        "tests/files/key_storage/JimiHendrix.key",  # Enter 2/2 the root`s private key path  # noqa
        "strongPass",  # Enter 2/2 the root`s private key password:
        "",  # [Optional] Give a name/tag to the key:
    ]
    input_step4 = [
        "y",  # Is the online key configuration correct? [y/n]
        "y",  # Is the root configuration correct? [y/n]
        "y",  # Is the targets configuration correct? [y/n]
        "y",  # Is the snapshot configuration correct? [y/n]
        "y",  # Is the timestamp configuration correct? [y/n]
        "y",  # Is the bins configuration correct? [y/n]
    ]

    return input_step1, input_step2, input_step3, input_step4


@pytest.fixture
def root() -> Metadata[Root]:
    return Metadata(Root(expires=datetime.now()))


@pytest.fixture
def root_info(root: Metadata[Root]) -> RootInfo:
    root_keys = [
        Key("id1", "ed25519", "", {"sha256": "abc"}),
        Key("id2", "ed25519", "", {"sha256": "foo"}),
    ]
    for key in root_keys:
        root.signed.add_key(key, "root")

    online_key = Key("id3", "ed25519", "", {"sha256": "doo"})
    for online_role in ["timestamp", "snapshot", "targets"]:
        root.signed.add_key(online_key, online_role)

    return RootInfo(root)


@pytest.fixture
def md_update_input() -> Tuple[List[str], List[str], List[str], List[str]]:
    # Step1 will combine current root file name and authorization.
    input_step1 = [
        "tests/files/root.json",  # File name or URL to the current root metadata  # noqa
        "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
    ]
    input_step2 = [
        "y",  # Do you want to extend the root's expiration? [y/n]
        "",  # Days to extend root's expiration starting from today (365)
        "y",  # New root expiration: YYYY-M-DD. Do you agree? [y/n]
    ]
    input_step3 = [
        "y",  # Do you want to modify root keys? [y/n]
        "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)
        "y",  # Do you want to remove a key [y/n]
        "Martin's Key",  # Name/Tag/ID prefix of the key to remove
        "n",  # Do you want to remove a key [y/n]
        "y",  # Do you want to add a new key? [y/n]
        "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
        "Kairo's Key",  # [Optional] Give a name/tag to the key
        "n",  # Do you want to add a new key? [y/n]
        "n",  # Do you want to modify root keys? [y/n]
    ]
    input_step4 = [
        "y",  # Do you want to change the online key? [y/n]
        "rsa",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/online-rsa.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
        "New RSA Online Key",  # [Optional] Give a name/tag to the key
        "n",  # Do you want to change the online key? [y/n]
    ]
    return input_step1, input_step2, input_step3, input_step4
