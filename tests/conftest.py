# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from tempfile import TemporaryDirectory

import pytest  # type: ignore
from click.testing import CliRunner  # type: ignore
from dynaconf import Dynaconf


@pytest.fixture
def test_context():
    setting_file = os.path.join(TemporaryDirectory().name, "test_settings.ini")
    test_settings = Dynaconf(settings_files=[setting_file])
    return {"settings": test_settings, "config": setting_file}


@pytest.fixture
def client():
    runner = CliRunner()
    return runner
