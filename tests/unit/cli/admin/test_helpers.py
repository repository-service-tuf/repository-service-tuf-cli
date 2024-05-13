# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import copy
from datetime import datetime, timezone
from unittest.mock import patch

import pretend
import pytest
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin import helpers
from tests.conftest import _HELPERS, _PEMS, _PROMPT


class TestHelpers:
    def test_load_signer_from_file_prompt(self, ed25519_key, monkeypatch):
        fake_click = pretend.stub(
            prompt=pretend.call_recorder(lambda *a, **kw: "hunter2")
        )
        monkeypatch.setattr(f"{_HELPERS}.click", fake_click)

        # success
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        assert isinstance(signer, CryptoSigner)
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        assert isinstance(signer, CryptoSigner)

        # fail with wrong file for key
        inputs = [f"{_PEMS / 'JC.rsa'}"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

        # fail with bad password
        fake_click.prompt = pretend.call_recorder(lambda *a, **kw: "hunter1")
        monkeypatch.setattr(f"{_HELPERS}.click", fake_click)
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

    def test_load_key_from_file_prompt(self):
        # success
        inputs = [f"{_PEMS / 'JH.pub'}"]
        with patch(_PROMPT, side_effect=inputs):
            key = helpers._load_key_from_file_prompt()

        assert isinstance(key, SSlibKey)

        # fail with wrong file
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(ValueError):
                _ = helpers._load_key_from_file_prompt()

    def test_load_key_prompt(self):
        fake_root = pretend.stub(keys={"123"})

        # return key
        fake_key = pretend.stub(keyid="abc")
        with patch(
            f"{_HELPERS}._load_key_from_file_prompt", return_value=fake_key
        ):
            key = helpers._load_key_prompt(fake_root)

        assert key == fake_key

        # return None - key in use
        fake_key = pretend.stub(keyid="123")
        with patch(
            f"{_HELPERS}._load_key_from_file_prompt", return_value=fake_key
        ):
            key = helpers._load_key_prompt(fake_root)

        assert key is None

        # return None - cannot load key
        for err in [OSError, ValueError]:
            with patch(
                f"{_HELPERS}._load_key_from_file_prompt", side_effect=err()
            ):
                key = helpers._load_key_prompt(fake_root)
                assert key is None

    def test_key_name_prompt(self):
        fake_key = pretend.stub(
            unrecognized_fields={helpers.KEY_NAME_FIELD: "taken"}
        )
        fake_root = pretend.stub(keys={"fake_key": fake_key})

        # iterate over name inputs until name is not empty and not taken
        inputs = ["", "taken", "new"]
        with patch(_PROMPT, side_effect=inputs):
            name = helpers._key_name_prompt(fake_root)

        assert name == "new"

    def test_expiry_prompt(self, patch_utcnow):
        # Assert bump expiry by days
        days_input = 10
        with patch(_PROMPT, side_effect=[str(days_input)]):
            result = helpers._expiry_prompt("root")

        expected = datetime(2025, 1, 10, 23, 59, 59, tzinfo=timezone.utc)
        assert result == (days_input, expected)  # see patch_utcnow

        # Assert prompt per-role default expiry
        for role in ["root", "timestamp", "snapshot", "targets", "bins"]:
            with patch(_PROMPT, side_effect=[""]):
                days, _ = helpers._expiry_prompt(role)

            assert days == helpers.DEFAULT_EXPIRY[role]

    def test_online_settings_prompt(self):
        test_data = [
            (
                [""] * 5,
                (
                    helpers._OnlineSettings(
                        helpers.DEFAULT_EXPIRY["timestamp"],
                        helpers.DEFAULT_EXPIRY["snapshot"],
                        helpers.DEFAULT_EXPIRY["targets"],
                        helpers.DEFAULT_EXPIRY["bins"],
                        helpers.DEFAULT_BINS_NUMBER,
                    )
                ),
            ),
            (
                ["1", "2", "3", "4", "2048"],
                helpers._OnlineSettings(1, 2, 3, 4, 2048),
            ),
        ]
        for inputs, expected in test_data:
            with patch(_PROMPT, side_effect=inputs):
                result = helpers._online_settings_prompt()

        assert result == expected

    def test_root_threshold_prompt(self):
        # prompt for threshold until positive integer
        inputs = ["-1", "0", "X", "5"]
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._root_threshold_prompt()
        assert result == 5

    def test_choose_add_remove_skip_key_prompt(self):
        # prompt for choice until in allowed range, default is disallowed
        inputs = ["-1", "", "2", "1"]
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._choose_add_remove_skip_key_prompt(1, False)
        assert result == 1

        # default allowed but cannot be entered explicitly
        inputs = ["-1", ""]
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._choose_add_remove_skip_key_prompt(1, True)
        assert result == -1

    def test_configure_root_keys_prompt(self, ed25519_key):
        # Configure root keys in empty root
        # NOTE: This is quite intricate but gives us full coverage
        # The course of action is:
        # 1. User is forced to add key to reach threshold (load: ed25519_key)
        # 2. User chooses to re-add key (choice: 0) but fails (load: None)
        # 3. User chooses to remove key (choice: 1)
        # 4. User is forced to add key to reach threshold (load: ed25519_key)
        # 5. User chooses to exit (choice: -1)

        root = Root()
        with (
            patch(
                f"{_HELPERS}._load_key_prompt",
                side_effect=[ed25519_key, None, ed25519_key],
            ),
            patch(f"{_HELPERS}._key_name_prompt", return_value="foo"),
            patch(
                f"{_HELPERS}._choose_add_remove_skip_key_prompt",
                side_effect=[0, 1, -1],
            ),
        ):
            helpers._configure_root_keys_prompt(root)

        assert ed25519_key.keyid in root.keys
        assert [ed25519_key.keyid] == root.roles["root"].keyids

    def test_configure_online_key_prompt(self, ed25519_key):
        # Create empty root
        root = Root()

        def _assert_online_key(key):
            id_ = key.keyid
            assert key == root.keys[id_]
            assert id_ not in root.roles["root"].keyids
            assert [id_] == root.roles["timestamp"].keyids
            assert [id_] == root.roles["snapshot"].keyids
            assert [id_] == root.roles["targets"].keyids
            assert (
                root.keys[id_].unrecognized_fields[helpers.KEY_URI_FIELD]
                == f"fn:{id_}"
            )
            assert (
                root.keys[id_].unrecognized_fields[helpers.KEY_NAME_FIELD]
                == "foo"
            )

        # Add new key (no user choice)
        with (
            patch(f"{_HELPERS}._load_key_prompt", return_value=ed25519_key),
            patch(f"{_HELPERS}._key_name_prompt", return_value="foo"),
        ):
            helpers._configure_online_key_prompt(root)

        _assert_online_key(ed25519_key)

        # Change key (two attempts)
        # 1. fail  (load returns None)
        # 2. succeed (load returns key2)
        key2 = copy.copy(ed25519_key)
        key2.keyid = "fake_keyid2"

        with (
            patch(_PROMPT, side_effect=[""]),  # default user choice: change
            patch(
                f"{_HELPERS}._load_key_prompt",
                side_effect=[None, key2],
            ),
            patch(f"{_HELPERS}._key_name_prompt", return_value="foo"),
        ):
            helpers._configure_online_key_prompt(root)

        _assert_online_key(key2)

        # Skip key change
        with patch(_PROMPT, side_effect=["N"]):  # user choice: skip
            helpers._configure_online_key_prompt(root)

        _assert_online_key(key2)

    def test_choose_signing_key_prompt(self):
        # prompt for choice until in allowed range, default is disallowed
        inputs = ["-1", "", "0", "2", "1"]
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._choose_signing_key_prompt(1, False)
        assert result == 1

        # default allowed but cannot be entered explicitly
        inputs = ["-1", ""]
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._choose_signing_key_prompt(1, True)
        assert result == -1

    def test_add_signature_prompt(self, ed25519_signer):
        metadata = Metadata(Root())
        # Sign until success (two attempts)
        # 1. load signer raises error
        # 2. load signer returns signer
        with patch(
            f"{_HELPERS}._load_signer_from_file_prompt",
            side_effect=[ValueError(), ed25519_signer],
        ):
            signature = helpers._add_signature_prompt(
                metadata, ed25519_signer.public_key
            )
        assert signature.keyid in metadata.signatures

    def test_add_root_signatures_prompt(self, ed25519_key):
        prev_root = pretend.stub()
        root_md = pretend.stub(
            signed=pretend.stub(),
            signed_bytes=pretend.stub(),
            signatures=pretend.stub(),
        )
        # Metadata fully verified (exit loop early)
        root_result = pretend.stub(verified=True)
        root_md.signed.get_root_verification_result = lambda *a: root_result
        helpers._add_root_signatures_prompt(root_md, prev_root)

        # Metadata not verified (run loop twice)
        # 1. choose key to sign (choose: 1)
        # 2. skip signing (choose: -1)
        root_result = pretend.stub(verified=False, signed=True)
        root_md.signed.get_root_verification_result = lambda *a: root_result
        keys = [ed25519_key]

        mock_add_sig = pretend.call_recorder(lambda root, key: None)

        with (
            patch(
                f"{_HELPERS}._filter_root_verification_results",
                return_value=pretend.stub(),
            ),
            patch(
                f"{_HELPERS}._print_keys_for_signing",
                return_value=keys,
            ),
            patch(
                f"{_HELPERS}._choose_signing_key_prompt",
                side_effect=[1, -1],
            ),
            patch(
                f"{_HELPERS}._add_signature_prompt",
                mock_add_sig,
            ),
        ):
            helpers._add_root_signatures_prompt(root_md, prev_root)

        assert mock_add_sig.calls == [pretend.call(root_md, ed25519_key)]

    def test_get_root_keys(self, ed25519_key):
        root = Root()
        ed25519_key2 = copy.copy(ed25519_key)
        ed25519_key2.keyid = "fake_keyid2"
        root.add_key(ed25519_key, "root")
        root.add_key(ed25519_key2, "root")

        keys = helpers._get_root_keys(root)
        assert keys == {
            ed25519_key.keyid: ed25519_key,
            ed25519_key2.keyid: ed25519_key2,
        }

    def test_get_online_key(self, ed25519_key):
        root = Root()
        assert not helpers._get_online_key(root)

        # NOTE: cli doesn't validate that all online roles have the same key
        root.add_key(ed25519_key, "timestamp")
        assert helpers._get_online_key(root) == ed25519_key

    def test_filter_root_verification_results(self):
        data = [
            (True, True, None, None, None, None, 0),
            (False, True, None, None, None, None, 1),
            (True, False, None, None, None, None, 1),
            (False, False, 1, 1, "foo", "foo", 1),
            (False, False, 1, 2, "foo", "foo", 2),
            (False, False, 1, 1, "foo", "bar", 2),
        ]

        for verif1, verif2, miss1, miss2, unsig1, unsig2, len_ in data:
            root_result = pretend.stub(
                first=pretend.stub(
                    verified=verif1, missing=miss1, unsigned=unsig1
                ),
                second=pretend.stub(
                    verified=verif2, missing=miss2, unsigned=unsig2
                ),
            )
            results = helpers._filter_root_verification_results(root_result)
            assert len(results) == len_, root_result

    def test_print_keys_for_signing(self, ed25519_key):
        ed25519_key2 = copy.copy(ed25519_key)
        ed25519_key2.keyid = "fake_keyid2"
        results = [
            pretend.stub(missing=1, unsigned={ed25519_key.keyid: ed25519_key}),
            pretend.stub(
                missing=1, unsigned={ed25519_key2.keyid: ed25519_key2}
            ),
        ]
        keys = helpers._print_keys_for_signing(results)
        assert keys == [ed25519_key, ed25519_key2]

    def test_print_root_keys(self, ed25519_key):
        ed25519_key2 = copy.copy(ed25519_key)
        ed25519_key2.keyid = "fake_keyid2"
        root = Root()
        root.add_key(ed25519_key, "root")
        root.add_key(ed25519_key2, "root")
        keys = helpers._print_root_keys(root)
        assert keys == [ed25519_key, ed25519_key2]
