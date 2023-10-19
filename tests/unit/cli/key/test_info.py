# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend

from repository_service_tuf.cli.key import info
from repository_service_tuf.helpers.tuf import RSTUFKey


class TestKeyInfoInteraction:
    def test_info(self, client, test_context, monkeypatch):
        input = [
            "",  # Choose key type [ed25519/ecdsa/rsa] (ed25519):
            "path/to/key.key",  # Enter the key's filename:
            "password",  # Enter the private key password:
        ]
        fake_load_key = pretend.call_recorder(
            lambda *a: RSTUFKey(
                key={
                    "keyid": "keyid",
                    "keytype": "keytype",
                    "scheme": "scheme",
                    "keyval": {"public": "k_public", "private": "private"},
                }
            )
        )
        monkeypatch.setattr(
            "repository_service_tuf.helpers.tuf.load_key", fake_load_key
        )
        result = client.invoke(
            info.info,
            input="\n".join(input),
            obj=test_context,
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert "keyid" in result.output
        assert "keytype" in result.output
        assert "scheme" in result.output
        assert "k_public" in result.output
        assert "k_private" not in result.output
        assert fake_load_key.calls == [
            pretend.call("path/to/key.key", "ed25519", "password", "")
        ]

    def test_info_failed_load_key(self, client, test_context, monkeypatch):
        input = [
            "",  # Choose key type [ed25519/ecdsa/rsa] (ed25519):
            "path/to/key.key",  # Enter the key's filename:
            "password",  # Enter the private key password:
        ]
        fake_load_key = pretend.call_recorder(
            lambda *a: RSTUFKey(key={}, error="Failed to load OH NO")
        )
        monkeypatch.setattr(
            "repository_service_tuf.helpers.tuf.load_key", fake_load_key
        )

        result = client.invoke(
            info.info, input="\n".join(input), obj=test_context
        )

        assert result.exit_code == 1
        assert "Failed to load OH NO" in result.output
        assert fake_load_key.calls == [
            pretend.call("path/to/key.key", "ed25519", "password", "")
        ]
