# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json

import pretend

from repository_service_tuf.cli.admin import update
from tests.conftest import _PAYLOADS, _PEMS, _ROOTS, invoke_command


class TestMetadataUpdate:
    def test_update(self, monkeypatch, client, patch_getpass, patch_utcnow):
        inputs = [
            "n",  # Do you want to change the expiry date? [y/n] (y)
            "n",  # Do you want to change the threshold? [y/n] (n)
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "JoeCocker's Key",  # Please enter a key name
            "y",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'cb20fa1061dde8e6267e0bef0981766aaadae168e917030f7f26edc7a0bab9c2.pub'}",  # Please enter path to public key  # noqa
            "New Online Key",  # Please enter a key name
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JJ.ecdsa'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JC.rsa'}",  # Please enter path to encrypted private key  # noqa
        ]
        args = [f"{_ROOTS / 'v1.json'}"]

        # selections interface
        selection_options = iter(
            (
                # adding/removing root public signing keys
                "remove",  # add key
                "JimiHendrix's Key",  # add key
                "add",  # remove key
                "continue",  # continue
                # signing with root keys
                "JimiHendrix's Key",  # select key to sign
                "JanisJoplin's Key",  # select key to sign
                "JoeCocker's Key",  # select key to sign
                "continue",  # continue
            )
        )
        mocked_select = pretend.call_recorder(
            lambda *a: next(selection_options)
        )

        # public key selection options
        monkeypatch.setattr(
            "repository_service_tuf.cli.admin.helpers._select", mocked_select
        )
        result = invoke_command(update.update, inputs, args)
        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
