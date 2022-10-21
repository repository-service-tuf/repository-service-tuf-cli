# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from dataclasses import dataclass
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional

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


@pytest.fixture
def fake_key():
    @dataclass
    class FakeKey:
        key: Optional[Dict[str, Any]] = None
        error: Optional[str] = None

    return FakeKey
