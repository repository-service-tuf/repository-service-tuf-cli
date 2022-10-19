# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from tempfile import TemporaryDirectory

import pytest  # type: ignore
from click.testing import CliRunner  # type: ignore
from dynaconf import Dynaconf
from securesystemslib.keys import generate_ed25519_key  # type: ignore


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
def fake_key():
    class FakeKey:
        def __init__(self):
            self.error = None
            self.key = generate_ed25519_key()

    return FakeKey
