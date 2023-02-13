# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from tempfile import TemporaryDirectory

import pytest  # type: ignore
from click.testing import CliRunner  # type: ignore
from dynaconf import Dynaconf

from repository_service_tuf.helpers.tuf import (
    Roles,
    RSTUFKey,
    ServiceSettings,
    Setup,
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
    setup = Setup(
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
        "y",  # Do you want start the ceremony?
        "",  # What Metadata expiration for root role?(Days)
        "",  # What is the number of keys for root role? (2)
        "",  # What is the key threshold for root role signing?
        "",  # What Metadata expiration for targets role?(Days) (365)?
        "y",  # Show example?
        "16",  # Choose the number of delegated hash bin roles
        "http://www.example.com/repository",  # What is the targets Base URL
        "",  # What Metadata expiration for snapshot role?(Days)
        "",  # What Metadata expiration for timestamp role?(Days)
        "",  # What Metadata expiration for bins role?(Days)
        "Y",  # Ready to start loading the keys? Passwords will be required for keys [y/n]  # noqa
    ]
    input_step2 = [
        "",  # hoose 1/1 ONLINE Key type [ed25519/ecdsa/rsa]
        "tests/files/online.key",  # Enter 1/1 the ONLINE`s Key path
        "strongPass",  # Enter 1/1 the ONLINE`s Key password
    ]
    input_step3 = [
        "",  # Choose 1/2 root Key type [ed25519/ecdsa/rsa]
        "tests/files/JanisJoplin.key",  # Enter 1/2 the root`s Key path
        "strongPass",  # Enter 1/2 the root`s Key password
        "",  # Choose 2/2 root Key type [ed25519/ecdsa/rsa]
        "tests/files/JimiHendrix.key",  # Enter 2/2 the root`s Key path
        "strongPass",  # Enter 2/2 the root`s Key password:
    ]
    input_step4 = [
        "y",  # Is Online Key configuration correct? [y/n]
        "y",  # Is root configuration correct? [y/n]
        "y",  # Is targets configuration correct? [y/n]
        "y",  # Is snapshot configuration correct? [y/n]
        "y",  # Is timestamp configuration correct? [y/n]
        "y",  # Is bins configuration correct? [y/n]
    ]

    return input_step1, input_step2, input_step3, input_step4
