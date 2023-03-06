# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from tempfile import TemporaryDirectory

import pytest  # type: ignore
from click.testing import CliRunner  # type: ignore
from dynaconf import Dynaconf

from repository_service_tuf.helpers.tuf import (
    BootstrapSetup,
    Roles,
    RSTUFKey,
    ServiceSettings,
)


@pytest.fixture
def test_context():
    setting_file = os.path.join(TemporaryDirectory().name, "test_settings.ini")
    test_settings = Dynaconf(settings_files=[setting_file])
    return {"settings": test_settings, "config": setting_file}


@pytest.fixture
def client():
    runner = CliRunner()
    return runner


@pytest.fixture
def test_setup():
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
        keys={
            Roles.ROOT: [],
            Roles.TARGETS: [],
            Roles.SNAPSHOT: [],
            Roles.TIMESTAMP: [],
            Roles.BINS: [],
        },
        online_key=RSTUFKey(),
    )

    return setup


@pytest.fixture
def test_inputs():
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
        "tests/files/online.key",  # Enter 1/1 the ONLINE`s private key path
        "strongPass",  # Enter 1/1 the ONLINE`s private key password
    ]
    input_step3 = [
        "",  # Choose 1/2 root key type [ed25519/ecdsa/rsa]
        "tests/files/JanisJoplin.key",  # Enter 1/2 the root`s private key path
        "strongPass",  # Enter 1/2 the root`s private key password
        "",  # Choose 2/2 root key type [ed25519/ecdsa/rsa]
        "tests/files/JimiHendrix.key",  # Enter 2/2 the root`s private key path
        "strongPass",  # Enter 2/2 the root`s private key password:
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
