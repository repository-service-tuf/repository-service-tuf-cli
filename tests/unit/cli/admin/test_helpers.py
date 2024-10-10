# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import copy
from datetime import datetime, timezone
from unittest.mock import patch

import click
import pretend
import pytest
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin import helpers
from tests.conftest import _HELPERS, _PEMS, _PROMPT


class TestHelpers:
    def test_load_signer_from_file_prompt(self, ed25519_key, monkeypatch):
        fake_click = pretend.stub(
            prompt=pretend.call_recorder(lambda *a, **kw: "hunter2"),
            style=pretend.call_recorder(lambda *a, **kw: ""),
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
        with (
            patch(
                f"{_HELPERS}._load_key_from_file_prompt", return_value=fake_key
            ),
            patch(
                f"{_HELPERS}._select",
                side_effect=[helpers.ROOT_SIGNERS.KEY_PEM],
            ),
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

    @pytest.mark.parametrize(
        "signer_type, prompt_values, signer_mock, expected_uri, expected_key",
        [
            # Test for KEY_PEM
            (
                helpers.ONLINE_SIGNERS.KEY_PEM,  # signer_type
                [],  # No prompt input needed for KEY_PEM
                f"{_HELPERS}._load_key_from_file_prompt",  # Mocked signer
                "fn:abc",  # Expected URI
                pretend.stub(keyid="abc"),  # Expected key object
            ),
            # Test for AWS KMS
            (
                helpers.ONLINE_SIGNERS.AWSKMS,
                ["aws-key-id"],
                f"{_HELPERS}.AWSSigner.import_",
                "aws-kms-uri",
                pretend.stub(keyid="abc"),
            ),
            # Test for GCP KMS
            (
                helpers.ONLINE_SIGNERS.GCPKMS,
                ["gcp-key-id"],
                f"{_HELPERS}.GCPSigner.import_",
                "gcp-kms-uri",
                pretend.stub(keyid="abc"),
            ),
            # Test for HashiCorp Vault (HV)
            (
                helpers.ONLINE_SIGNERS.HV,
                ["hv-key-name"],
                f"{_HELPERS}.VaultSigner.import_",
                "hv-uri",
                pretend.stub(keyid="abc"),
            ),
            # Test for Azure KMS
            (
                helpers.ONLINE_SIGNERS.AZKMS,
                ["azure-vault", "azure-key"],
                f"{_HELPERS}.AzureSigner.import_",
                "az-kms-uri",
                pretend.stub(keyid="abc"),
            ),
        ],
    )
    def test_load_online_key_prompt_success_cases(
        self,
        signer_type,
        prompt_values,
        signer_mock,
        expected_uri,
        expected_key,
    ):
        fake_root = pretend.stub(keys={})

        # Mocking the necessary methods based on the signer type
        if signer_type == helpers.ONLINE_SIGNERS.KEY_PEM:
            return_value = expected_key
        else:
            return_value = (expected_uri, expected_key)
        with patch(signer_mock, return_value=return_value):
            if prompt_values:
                with patch(
                    f"{_HELPERS}.Prompt.ask", side_effect=prompt_values
                ):
                    uri, key = helpers._load_online_key_prompt(
                        fake_root, signer_type.value
                    )
            else:
                uri, key = helpers._load_online_key_prompt(
                    fake_root, signer_type.value
                )

        assert uri == expected_uri
        assert key == expected_key

    def test_load_online_key_prompt_key_already_in_use(self):
        # Mocked root object with a preloaded key
        fake_root = pretend.stub(keys={"abc"})
        fake_key = pretend.stub(keyid="abc")

        with patch(
            f"{_HELPERS}._load_key_from_file_prompt", return_value=fake_key
        ):
            uri, key = helpers._load_online_key_prompt(
                fake_root, helpers.ONLINE_SIGNERS.KEY_PEM
            )

        assert key is None
        assert uri is None

    @pytest.mark.parametrize(
        "signer_type, exception",
        [
            ("KEY_PEM", OSError),
            ("KEY_PEM", ValueError),
        ],
    )
    def test_load_online_key_prompt_exception_handling(
        self, signer_type, exception
    ):
        fake_root = pretend.stub(keys={})

        with patch(
            f"{_HELPERS}._load_key_from_file_prompt", side_effect=exception
        ):
            uri, key = helpers._load_online_key_prompt(
                fake_root, getattr(helpers.ONLINE_SIGNERS, signer_type)
            )

        assert key is None
        assert uri is None

    def test_key_name_prompt(self):
        fake_key = pretend.stub(
            unrecognized_fields={helpers.KEY_NAME_FIELD: "taken"}
        )
        fake_root = pretend.stub(keys={"fake_key": fake_key})

        # iterate over name inputs until name is not empty and not taken
        inputs = ["", "taken", "new"]
        with patch(_PROMPT, side_effect=inputs):
            name = helpers._key_name_prompt(fake_root.keys)

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

    def test_settings_prompt(self):
        test_data = [
            (
                [""] * 5,
                (
                    helpers._Settings(
                        helpers.DEFAULT_EXPIRY["timestamp"],
                        helpers.DEFAULT_EXPIRY["snapshot"],
                        helpers.DEFAULT_EXPIRY["targets"],
                    )
                ),
            ),
            (
                ["1", "2", "3"],
                helpers._Settings(1, 2, 3),
            ),
        ]
        for inputs, expected in test_data:
            with patch(_PROMPT, side_effect=inputs):
                result = helpers._settings_prompt()

        assert result == expected

    def test__threshold_prompt(self):
        # prompt for threshold until positive integer
        inputs = ["-1", "0", "X", "5"]
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._threshold_prompt("root")
        assert result == 5

    def test_configure_root_keys_prompt(self, ed25519_key):
        # Configure root keys in empty root
        root = Root()
        with (
            patch(
                f"{_HELPERS}._load_key_prompt",
                side_effect=[ed25519_key, None, ed25519_key],
            ),
            patch(f"{_HELPERS}._key_name_prompt", return_value="foo"),
            patch(
                f"{_HELPERS}._select",
                side_effect=["add", "add", "continue", "Key PEM File"],
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
            patch(
                f"{_HELPERS}._load_online_key_prompt",
                return_value=(f"fn:{ed25519_key.keyid}", ed25519_key),
            ),
            patch(f"{_HELPERS}._key_name_prompt", return_value="foo"),
            patch(
                f"{_HELPERS}._select",
                side_effect=["Key PEM File"],
            ),
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
                f"{_HELPERS}._load_online_key_prompt",
                side_effect=[(None, None), (f"fn:{key2.keyid}", key2)],
            ),
            patch(f"{_HELPERS}._key_name_prompt", return_value="foo"),
            patch(
                f"{_HELPERS}._select",
                side_effect=["Key PEM File", "Key PEM File"],
            ),
        ):
            helpers._configure_online_key_prompt(root)

        _assert_online_key(key2)

        # Skip key change
        with patch(_PROMPT, side_effect=["N"]):  # user choice: skip
            helpers._configure_online_key_prompt(root)

        _assert_online_key(key2)

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
                f"{_HELPERS}._select", side_effect=["fake_keyid", "continue"]
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

    def test__parse_pending_data(self):
        md_data = {"signed": {"_type": "root"}}
        result = helpers._parse_pending_data(
            {"data": {"metadata": {"root": md_data}}}
        )

        assert result == {"root": md_data}

    def test__parse_pending_data_custom_delegation(self):
        md_data = {"signed": {"_type": "targets"}}
        result = helpers._parse_pending_data(
            {"data": {"metadata": {"custom_target": md_data}}}
        )

        assert result == {"custom_target": md_data}

    def test__parse_pending_not_root_or_targets_type(self):
        md_data = {"signed": {"_type": "timestamp"}}
        with pytest.raises(click.ClickException) as e:
            helpers._parse_pending_data(
                {"data": {"metadata": {"timestamp": md_data}}}
            )

        assert "Supporting only root and targets pending role types" in str(e)

    def test__parse_pending_data_missing_metadata(self):
        with pytest.raises(click.ClickException) as e:
            helpers._parse_pending_data({"data": {}})

        assert "No metadata available for signing" in str(e)

    def test__parse_pending_data_all_trusted_metadata(self):
        data = {"data": {"trusted_root": "Foo", "trusted_targets": "Bar"}}
        with pytest.raises(click.ClickException) as e:
            helpers._parse_pending_data(data)

        assert "No metadata available for signing" in str(e)

    def test__get_pending_roles_request(self, monkeypatch):
        fake_settings = pretend.stub(SERVER=None)
        fake_json = pretend.stub()
        response = pretend.stub(
            status_code=200, json=pretend.call_recorder(lambda: fake_json)
        )
        helpers.request_server = pretend.call_recorder(
            lambda *a, **kw: response
        )

        parsed_data = pretend.stub()
        fake__parse_pending_data = pretend.call_recorder(lambda a: parsed_data)
        monkeypatch.setattr(
            helpers, "_parse_pending_data", fake__parse_pending_data
        )

        result = helpers._get_pending_roles(fake_settings)

        assert result == parsed_data
        assert helpers.request_server.calls == [
            pretend.call(
                fake_settings.SERVER,
                helpers.URL.METADATA_SIGN.value,
                helpers.Methods.GET,
            )
        ]
        assert response.json.calls == [pretend.call()]
        assert fake__parse_pending_data.calls == [pretend.call(fake_json)]

    def test__get_pending_roles_request_bad_status_code(self):
        fake_settings = pretend.stub(
            SERVER="http://localhost:80",
        )
        response = pretend.stub(status_code=400, text="")
        helpers.request_server = pretend.call_recorder(
            lambda *a, **kw: response
        )
        with pytest.raises(click.ClickException) as e:
            helpers._get_pending_roles(fake_settings)

        assert "Failed to fetch metadata for signing" in str(e)
        assert helpers.request_server.calls == [
            pretend.call(
                fake_settings.SERVER,
                helpers.URL.METADATA_SIGN.value,
                helpers.Methods.GET,
            )
        ]

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

    def test__select(self, monkeypatch):
        helpers.beaupy.select = pretend.call_recorder(
            lambda *a, **kw: "option1"
        )
        result = helpers._select(["option1", "option2"])

        assert result == "option1"
        assert helpers.beaupy.select.calls == [
            pretend.call(
                options=["option1", "option2"], cursor=">", cursor_style="cyan"
            )
        ]

    def test__get_latest_md_root_not_exists(self, monkeypatch):
        fake_dir_name = "foo_bar_dir"

        class FakeTempDir:
            def __init__(self) -> None:
                self.name = fake_dir_name

        monkeypatch.setattr(f"{_HELPERS}.TemporaryDirectory", FakeTempDir)
        fake_response = pretend.stub(status_code=200, text="foo bar")
        fake_requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        monkeypatch.setattr(f"{_HELPERS}.requests", fake_requests)

        # mock "open()"
        fake_destination_file = pretend.stub(
            write=pretend.call_recorder(lambda *a: None),
            flush=pretend.call_recorder(lambda: None),
            fileno=pretend.call_recorder(lambda: "fileno"),
        )

        class FakeFileDescriptor:
            def __init__(self, file, mode):
                return None

            def __enter__(self):
                return fake_destination_file

            def __exit__(self, type, value, traceback):
                pass

        monkeypatch.setitem(
            helpers.__builtins__, "open", lambda *a: FakeFileDescriptor(*a)
        )

        class FakeUpdater:
            def __init__(self, **kw) -> None:
                self.new_args = kw
                self.refresh_calls_amount = 0

            def refresh(self) -> None:
                self.refresh_calls_amount += 1

            def _load_local_metadata(self, *a):
                return fake_metadata

        monkeypatch.setattr(f"{_HELPERS}.Updater", FakeUpdater)
        fake_root_result = pretend.stub()
        fake_metadata = pretend.stub(
            from_bytes=pretend.call_recorder(lambda a: fake_root_result)
        )
        monkeypatch.setattr(f"{_HELPERS}.Metadata", fake_metadata)
        fake_url = "http://localhost:8080"

        result = helpers._get_latest_md(fake_url, Root.type)

        assert result == fake_root_result
        assert fake_requests.get.calls == [
            pretend.call(f"{fake_url}/1.root.json", timeout=300)
        ]
        assert fake_destination_file.write.calls == [
            pretend.call(fake_response.text)
        ]
        assert fake_metadata.from_bytes.calls == [
            pretend.call(FakeUpdater._load_local_metadata(Root.type))
        ]

    def test__get_latest_md_root_not_exist_response_not_200(self, monkeypatch):
        fake_dir_name = "foo_bar_dir"

        class FakeTempDir:
            def __init__(self) -> None:
                self.name = fake_dir_name

        monkeypatch.setattr(f"{_HELPERS}.TemporaryDirectory", FakeTempDir)
        fake_response = pretend.stub(status_code=400)
        fake_requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        monkeypatch.setattr(f"{_HELPERS}.requests", fake_requests)

        fake_url = "http://localhost:8080"

        with pytest.raises(click.ClickException) as e:
            helpers._get_latest_md(fake_url, Root.type)

        assert "Cannot fetch initial root " in str(e)

    def test__get_latest_md_root_OS_error(self, monkeypatch):
        fake_dir_name = "foo_bar_dir"

        class FakeTempDir:
            def __init__(self) -> None:
                self.name = fake_dir_name

        monkeypatch.setattr(f"{_HELPERS}.TemporaryDirectory", FakeTempDir)
        fake_url = "http://localhost:8080"

        with pytest.raises(click.ClickException) as e:
            helpers._get_latest_md(fake_url, Root.type)

        assert "Problem fetching latest" in str(e)
