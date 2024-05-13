# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json
from unittest.mock import patch

import click
import pretend
import pytest

from repository_service_tuf.cli.admin import sign
from tests.conftest import _PAYLOADS, _PEMS, _ROOTS, invoke_command


class TestSign:
    def test_sign(self, client, patch_getpass):
        inputs = [
            "2",  # Please enter signing key index
            f"{_PEMS / 'JC.rsa'}",  # Please enter path to encrypted private key  # noqa
        ]
        args = [
            f"{_ROOTS / 'v2.json'}",
            f"{_ROOTS / 'v1.json'}",
        ]
        result = invoke_command(client, sign.sign, inputs, args)

        with open(_PAYLOADS / "sign.json") as f:
            expected = json.load(f)

        assert result.data["role"] == "root"
        assert (
            result.data["signature"]["keyid"] == expected["signature"]["keyid"]
        )


class TestSignError:
    def test_sign_missing_previous(self, client):
        with pytest.raises(click.ClickException) as e:
            sign.sign.main([f"{_ROOTS / 'v2.json'}"], standalone_mode=False)
        assert "v1 needed" in str(e)

    def test_sign_already_signed(self, client):
        # Construct fake root metadata with "verified" fake verification result
        fake_result = pretend.stub(verified=True)
        fake_root = pretend.stub(
            version=1, get_root_verification_result=lambda *a: fake_result
        )
        fake_metadata = pretend.stub(
            signed=fake_root, signed_bytes=None, signatures=None
        )

        # Click still needs a real file passed, even if it is ignored
        args = [f"{_ROOTS / 'v1.json'}"]
        with patch(
            "repository_service_tuf.cli.admin.sign.Metadata.from_bytes",
            side_effect=lambda x: fake_metadata,
        ):
            with pytest.raises(click.ClickException) as e:
                sign.sign.main(args, standalone_mode=False)

            assert "fully signed" in str(e)
