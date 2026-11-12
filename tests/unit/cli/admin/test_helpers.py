# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import copy
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import click
import pretend
import pytest
from email_validator import EmailNotValidError
from PyKCS11 import CKR_USER_NOT_LOGGED_IN, PyKCS11Error  # type: ignore
from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import CryptoSigner, SigstoreKey, SSlibKey
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    Root,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)

from repository_service_tuf.cli.admin import helpers
from repository_service_tuf.helpers.api_client import URL, Methods
from tests.conftest import _HELPERS, _PEMS, _PROMPT, _PROMPT_TOOLKIT


class TestHelpers:
    def test__get_secret(self, monkeypatch):
        monkeypatch.setattr(
            f"{_HELPERS}.click",
            pretend.stub(
                prompt=pretend.call_recorder(lambda *a, **kw: "hunter2"),
            ),
        )

        result = helpers._get_secret("secret")
        assert result == "hunter2"
        assert helpers.click.prompt.calls == [
            pretend.call(
                (
                    "\nEnter secret to sign (provide touch/bio authentication "
                    "if needed)"
                ),
                hide_input=True,
            )
        ]

    def test_load_signer_from_file_prompt(self, ed25519_key, monkeypatch):
        fake_click = pretend.stub(
            prompt=pretend.call_recorder(lambda *a, **kw: "hunter2"),
            style=pretend.call_recorder(lambda *a, **kw: ""),
        )
        monkeypatch.setattr(f"{_HELPERS}.click", fake_click)

        # success
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        assert isinstance(signer, CryptoSigner)
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        assert isinstance(signer, CryptoSigner)

        # fail with wrong file for key
        inputs = [f"{_PEMS / 'JC.rsa'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

        # give key without password and good key after
        inputs = [
            f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043'}",  # noqa
            f"{_PEMS / 'JH.ed25519'}",
        ]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        # fail with bad password
        fake_click.prompt = pretend.call_recorder(lambda *a, **kw: "hunter1")
        monkeypatch.setattr(f"{_HELPERS}.click", fake_click)
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

    def test_load_key_from_file_prompt(self):
        # success
        inputs = [f"{_PEMS / 'JH.pub'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            key = helpers._load_key_from_file_prompt()

        assert isinstance(key, SSlibKey)

        # fail with wrong file
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            with pytest.raises(ValueError):
                _ = helpers._load_key_from_file_prompt()

    def test_load_signer_from_hsm_prompt(self, hsm_signer, hsm_cert):
        with (
            patch("os.path.exists", return_value=True),
            patch(
                f"{_HELPERS}.HSMSigner.import_",
                return_value=("hsm:2?label=YubiKey+PIV+%2315835999", "pb"),
            ),
            patch(f"{_HELPERS}._get_secret", return_value="hunter2"),
            patch(
                f"{_HELPERS}.Signer.from_priv_key_uri",
                return_value=hsm_signer,
            ),
        ):
            result = helpers._load_signer_from_hsm_prompt(hsm_cert)

            assert result == hsm_signer

    def test_load_signer_from_hsm_prompt_no_libykcs11(self):
        with (patch("os.path.exists", return_value=False),):
            with pytest.raises(click.ClickException) as err:
                helpers._load_signer_from_hsm_prompt("fake-key")

                assert "Failed to find libykcs11" in str(err)

    def test_load_key_from_hsm_prompt(self):
        # success
        inputs = [f"{_PEMS / 'hsm-9c-ecc.crt'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            key = helpers._load_key_from_hsm_prompt()

        assert isinstance(key, SSlibKey)

        # fail with wrong file
        inputs = [f"{_PEMS / 'JH.ed25519'}"]
        with patch(_PROMPT_TOOLKIT, side_effect=inputs):
            with pytest.raises(ValueError):
                _ = helpers._load_key_from_hsm_prompt()

    @pytest.mark.parametrize(
        "signer_type, key_load",
        [
            (helpers.ROOT_SIGNERS.KEY_PEM, "_load_key_from_file_prompt"),
            (helpers.ROOT_SIGNERS.HSM, "_load_key_from_hsm_prompt"),
        ],
    )
    def test_load_key_prompt(self, signer_type, key_load):
        fake_root = pretend.stub(keys={"123"})

        # return key
        fake_key = pretend.stub(keyid="abc")
        with (
            patch(f"{_HELPERS}.{key_load}", return_value=fake_key),
            patch(
                f"{_HELPERS}._select",
                side_effect=[signer_type],
            ),
        ):
            key = helpers._load_key_prompt(fake_root)

        assert key == fake_key

        # return None - key in use
        fake_key = pretend.stub(keyid="123")
        with (
            patch(
                f"{_HELPERS}._load_key_from_file_prompt", return_value=fake_key
            ),
            patch(
                f"{_HELPERS}._select",
                side_effect=[helpers.ROOT_SIGNERS.KEY_PEM],
            ),
        ):
            key = helpers._load_key_prompt(fake_root.keys, duplicate=False)

        assert key is None

        # return None - cannot load key
        for err in [OSError, ValueError]:
            with (
                patch(
                    f"{_HELPERS}._load_key_from_file_prompt",
                    side_effect=err(),
                ),
                patch(
                    f"{_HELPERS}._select",
                    side_effect=[helpers.ROOT_SIGNERS.KEY_PEM],
                ),
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

    def test_delegated_target_role_name_success_first_try(self):
        """Test that entering a valid name immediately succeeds."""
        with patch(
            "rich.prompt.Prompt.ask", return_value="my-delegated-role"
        ) as mock_ask:
            result = helpers._delegated_target_role_name_prompt()

            assert mock_ask.call_count == 1
            assert result == "my-delegated-role"

    def test_delegated_target_role_name_retry_on_empty(self):
        """Test an empty in leadin to warning and loops until a valid in"""
        with patch(
            "rich.prompt.Prompt.ask", side_effect=["", "", "my-delegated-role"]
        ) as mock_ask:
            result = helpers._delegated_target_role_name_prompt()

            # Prompt.ask is called 3 times: twice for empty strings,
            # once for the valid name
            assert mock_ask.call_count == 3
            assert result == "my-delegated-role"

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

    def test_add_signature_prompt_using_pem(self, ed25519_signer):
        metadata = Metadata(Root())
        # Sign until success (two attempts)
        # 1. load signer raises error
        # 2. load signer returns signer
        with (
            patch(
                f"{_HELPERS}._load_signer_from_file_prompt",
                side_effect=[
                    ValueError(),
                    UnverifiedSignatureError(),
                    ed25519_signer,
                ],
            ),
            patch(
                f"{_HELPERS}._select",
                return_value=helpers.ROOT_SIGNERS.KEY_PEM,
            ),
        ):
            signature = helpers._add_signature_prompt(
                metadata, ed25519_signer.public_key
            )
        assert signature.keyid in metadata.signatures

    def test_add_signature_prompt_using_hsm(self, hsm_signer):
        metadata = Metadata(Root())
        # Sign until success (two attempts)
        # 1. load signer raises error
        # 2. load signer returns signer
        mocked_exception = ValueError()
        mocked_exception.__context__ = PyKCS11Error(
            value=CKR_USER_NOT_LOGGED_IN
        )
        with (
            patch(
                f"{_HELPERS}._load_signer_from_hsm_prompt",
                side_effect=[mocked_exception, hsm_signer],
            ),
            patch(
                f"{_HELPERS}._select",
                return_value=helpers.ROOT_SIGNERS.HSM,
            ),
        ):
            signature = helpers._add_signature_prompt(
                metadata, hsm_signer.public_key
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

    def test_path_prompt_retry_and_success(self):
        """Test that empty => warning/retry, but valid path succeeds."""
        with patch(
            "rich.prompt.Prompt.ask", side_effect=["", "targets/releases/*"]
        ) as mock_ask:
            result = helpers._path_prompt()

            assert mock_ask.call_count == 2
            assert result == "targets/releases/*"

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

    def test_get_online_key_without_keyids(self):
        """Test _get_online_key when timestamp role has empty keyids."""
        mock_root = MagicMock()
        mock_root.roles = {Timestamp.type: MagicMock(keyids=[])}

        key = helpers._get_online_key(mock_root)
        assert key is None

    def test__parse_pending_data(self):
        fake_md = {"root": Metadata(Root()).to_dict()}
        result = helpers._parse_pending_data({"data": {"metadata": fake_md}})

        assert result == fake_md

    def test__parse_pending_data_missing_metadata(self):
        with pytest.raises(click.ClickException) as e:
            helpers._parse_pending_data({"data": {}})

        assert "No metadata available for signing" in str(e)

    def test_parse_pending_data_unsupported_role_type(self):
        """Test _parse_pending_data raises ClickException for unsupported
        pending role types."""
        response = {
            "data": {
                "metadata": {
                    "unsupported_role": {
                        "signed": {"_type": "UnsupportedType"}
                    }
                }
            }
        }

        with pytest.raises(
            click.ClickException,
            match="Supporting only root and targets pending role types",
        ):
            helpers._parse_pending_data(response)

    def test_get_online_key_with_keyids(self):
        """Test _get_online_key when timestamp role has keyids."""
        mock_root = MagicMock()
        mock_key = MagicMock()
        mock_root.roles = {Timestamp.type: MagicMock(keyids=["key1"])}
        mock_root.get_key.return_value = mock_key

        key = helpers._get_online_key(mock_root)
        assert key == mock_key
        mock_root.get_key.assert_called_once_with("key1")

    def test__get_pending_roles_request(self, monkeypatch):
        fake_settings = pretend.stub(SERVER=None, HEADERS=None)
        fake_json = pretend.stub()
        response = pretend.stub(
            status_code=200, json=pretend.call_recorder(lambda: fake_json)
        )
        fake_request_server = pretend.call_recorder(lambda *a, **kw: response)
        monkeypatch.setattr(helpers, "request_server", fake_request_server)

        parsed_data = pretend.stub()
        fake__parse_pending_data = pretend.call_recorder(lambda a: parsed_data)
        monkeypatch.setattr(
            helpers, "_parse_pending_data", fake__parse_pending_data
        )

        result = helpers._get_pending_roles(fake_settings)

        assert result == parsed_data
        assert fake_request_server.calls == [
            pretend.call(
                fake_settings.SERVER,
                URL.METADATA_SIGN.value,
                Methods.GET,
                headers=None,
            )
        ]
        assert response.json.calls == [pretend.call()]
        assert fake__parse_pending_data.calls == [pretend.call(fake_json)]

    def test__get_pending_roles_request_bad_status_code(self, monkeypatch):
        fake_settings = pretend.stub(
            SERVER="http://localhost:80",
            HEADERS=None,
        )
        response = pretend.stub(status_code=400, text="")
        fake_request_server = pretend.call_recorder(lambda *a, **kw: response)
        monkeypatch.setattr(helpers, "request_server", fake_request_server)
        with pytest.raises(click.ClickException) as e:
            helpers._get_pending_roles(fake_settings)

        assert "Failed to fetch metadata for signing" in str(e)
        assert fake_request_server.calls == [
            pretend.call(
                fake_settings.SERVER,
                URL.METADATA_SIGN.value,
                Methods.GET,
                headers=None,
            )
        ]

    def test_print_root_no_online_key(self):
        """Test _print_root when no online key is configured."""
        root_mock = MagicMock(spec=Root)

        with (
            patch(f"{_HELPERS}._get_root_keys", return_value={}),
            patch(
                f"{_HELPERS}._get_online_key", return_value=None
            ) as mock_get_online,
            patch(f"{_HELPERS}.console.print") as mock_console_print,
        ):

            helpers._print_root(root_mock)

            mock_get_online.assert_called_once_with(root_mock)
            mock_console_print.assert_called_once_with(
                "No online key configured"
            )

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
        fake_response = pretend.stub(
            status_code=200,
            text="foo bar",
            content=b"foo bar",
        )
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

        created_updaters: list[dict] = []

        class FakeUpdater:
            def __init__(self, **kw) -> None:
                created_updaters.append(kw)
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
            pretend.call(fake_response.content)
        ]
        assert created_updaters == [
            {
                "metadata_dir": fake_dir_name,
                "metadata_base_url": fake_url,
                "bootstrap": fake_response.content,
            }
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

        # The error message can be either "Cannot fetch initial root" or
        # "Problem fetching latest root" depending on the exception path
        error_msg = str(e.value)
        assert "fetch" in error_msg.lower() and "root" in error_msg.lower()

    def test_load_key_from_sigstore_prompt(self):
        fake_issuer = "Google"
        helpers._select = pretend.call_recorder(lambda *a, **kw: fake_issuer)
        # success
        inputs = ["abc@gmail.com"]
        with patch(_PROMPT, side_effect=inputs):
            key = helpers._load_key_from_sigstore_prompt()

        assert isinstance(key, SigstoreKey)
        assert key.keyval == {
            "identity": inputs[0],
            "issuer": helpers.SIGSTORE_ISSUERS.Google.value,
        }
        assert helpers._select.calls == [
            pretend.call(helpers.SIGSTORE_ISSUERS.names())
        ]

        # fail with non-email identity
        inputs = ["abc"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(EmailNotValidError):
                helpers._load_key_from_sigstore_prompt()

        # fail with blank identity
        inputs = [""]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(EmailNotValidError):
                helpers._load_key_from_sigstore_prompt()

    def test_configure_delegations_paths_init_none_and_continue(self):
        """Test when paths is [], prompts for path, then continues."""
        delegated_role = MagicMock(name="DelegatedRole")
        delegated_role.name = "role-1"
        delegated_role.paths = None  # Triggers line: delegated_role.paths = []

        # 1st: _path_prompt will call Prompt.ask for the initial path
        # 2nd: _select will choose "continue"
        with (
            patch("rich.prompt.Prompt.ask", return_value="path/a"),
            patch(
                f"{_HELPERS}._select", return_value="continue"
            ) as mock_select,
        ):

            result = helpers._configure_delegations_paths(delegated_role)

            assert delegated_role.paths == ["path/a"]
            mock_select.assert_called_once_with(
                ["continue", "add new path", "remove path"]
            )
            assert result == delegated_role

    def test__configure_delegations_paths_add_then_continue(self):
        delegated_role = DelegatedRole(
            name="testrole", threshold=1, keyids=[], terminating=True, paths=[]
        )
        with (
            patch(f"{_HELPERS}._path_prompt", return_value="project-a/*"),
            patch(f"{_HELPERS}._select", side_effect=["continue"]),
        ):
            result = helpers._configure_delegations_paths(delegated_role)

        assert result.paths == ["project-a/*"]

    def test__configure_delegations_paths_empty_forces_add(self):
        delegated_role = DelegatedRole(
            name="testrole", threshold=1, keyids=[], terminating=True, paths=[]
        )
        with (
            patch(
                f"{_HELPERS}._path_prompt",
                side_effect=["first/*", "second/*"],
            ),
            patch(
                f"{_HELPERS}._select", side_effect=["add new path", "continue"]
            ),
        ):
            result = helpers._configure_delegations_paths(delegated_role)

        assert "first/*" in result.paths
        assert "second/*" in result.paths

    def test__configure_delegations_paths_remove(self):
        delegated_role = DelegatedRole(
            name="testrole",
            threshold=1,
            keyids=[],
            terminating=True,
            paths=["old/*"],
        )
        with (
            patch(f"{_HELPERS}._path_prompt", return_value="new/*"),
            patch(
                f"{_HELPERS}._select",
                side_effect=[
                    "remove path",
                    "old/*",
                    "add new path",
                    "continue",
                ],
            ),
        ):
            result = helpers._configure_delegations_paths(delegated_role)

        assert "old/*" not in result.paths
        assert "new/*" in result.paths

    def test__configure_delegations_keys_add_key(self, ed25519_key):
        delegated_role = DelegatedRole(
            name="testrole", threshold=1, keyids=[], terminating=True, paths=[]
        )
        delegations = Delegations(keys={}, roles={})
        with (
            patch(f"{_HELPERS}._load_key_prompt", return_value=ed25519_key),
            patch(f"{_HELPERS}._key_name_prompt", return_value="mykey"),
            patch(f"{_HELPERS}._select", side_effect=["continue"]),
        ):
            helpers._configure_delegations_keys(delegated_role, delegations)

        assert ed25519_key.keyid in delegated_role.keyids
        assert ed25519_key.keyid in delegations.keys

    def test__configure_delegations_keys_load_returns_none_retries(
        self, ed25519_key
    ):
        delegated_role = DelegatedRole(
            name="testrole", threshold=1, keyids=[], terminating=True, paths=[]
        )
        delegations = Delegations(keys={}, roles={})
        with (
            patch(
                f"{_HELPERS}._load_key_prompt",
                side_effect=[None, ed25519_key],
            ),
            patch(f"{_HELPERS}._key_name_prompt", return_value="mykey"),
            patch(f"{_HELPERS}._select", side_effect=["continue"]),
        ):
            helpers._configure_delegations_keys(delegated_role, delegations)

        assert ed25519_key.keyid in delegated_role.keyids

    def test_configure_delegations_roles_none_initialization(self):
        """Test adding a new delegation when roles is initialized to None."""
        mock_delegations = MagicMock(spec=Delegations)
        mock_delegations.keys = {}
        mock_delegations.roles = None  # Triggers lines 915-916: roles = {}

        def side_effect_delegations(*args, **kwargs):
            return mock_delegations

        with (
            patch(
                f"{_HELPERS}.Delegations", side_effect=side_effect_delegations
            ),
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                return_value="new-role",
            ),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(f"{_HELPERS}._configure_delegations_paths"),
            patch(
                f"{_HELPERS}._select",
                side_effect=["Online Key (use the existing)", "continue"],
            ),
            patch(f"{_HELPERS}._print_delegation"),
        ):

            helpers._configure_delegations()
            assert "new-role" in mock_delegations.roles

    def test_configure_delegations_keys_remove_raises_not_implemented(self):
        """Test selecting 'remove' in delegation keys raises."""
        delegated_role = MagicMock(spec=DelegatedRole)
        delegated_role.keyids = ["key-1"]
        delegated_role.threshold = 1

        delegations = MagicMock(spec=Delegations)
        delegations.keys = {"key-1": MagicMock()}

        # _select chooses "remove"
        with (
            patch(f"{_HELPERS}._select", return_value="remove"),
            patch(f"{_HELPERS}._print_missing_key_info"),
        ):

            with pytest.raises(NotImplementedError, match="TODO"):
                helpers._configure_delegations_keys(
                    delegated_role, delegations
                )

    def test_configure_delegations_overwrite_decline_and_continue(self):
        """Test add an existing delegation name but declining to overwrite."""
        delegations = Delegations(keys={}, roles={})
        # Pre-populate a role so it triggers the overwrite check
        existing_role = DelegatedRole(
            name="existing-role",
            keyids=[],
            threshold=1,
            terminating=True,
            paths=[],
        )
        delegations.roles["existing-role"] = existing_role

        # 1. _select chooses "add new delegation" when prompted, then
        # "continue" to exit
        # 2. _delegated_target_role_name_prompt returns "existing-role"
        # 3. Confirm.ask returns False (decline overwrite -> hits continue)
        with (
            patch(
                f"{_HELPERS}._select",
                side_effect=["add new delegation", "continue"],
            ),
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                return_value="existing-role",
            ),
            patch("rich.prompt.Confirm.ask", return_value=False),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(
                f"{_HELPERS}._configure_delegations_paths", return_value=None
            ),
            patch(f"{_HELPERS}._print_delegation") as mock_print_del,
        ):

            # Pre-populate a role in the function's internal structure by
            # mocking  Delegations or letting it run. Since
            # _configure_delegations creates a  fresh Delegations object, we
            # can verify it breaks out cleanly on "continue".
            result = helpers._configure_delegations()
            assert isinstance(result, Delegations)
            mock_print_del.assert_called_once()

    def test_configure_delegations_add_keys_flow(self):
        """Test add a new delegation with 'Add Keys' signing method"""
        delegations = Delegations(keys={}, roles={})
        # Force roles to None to test `if delegations.roles is None:` branch
        delegations.roles = None

        # Sequence:
        # 1. _delegated_target_role_name_prompt returns "new-role"
        # 2. _expiry_prompt returns (30, None)
        # 3. _configure_delegations_paths passes through
        # 4. _select chooses "Add Keys"
        # 5. _threshold_prompt returns 1
        # 6. _configure_delegations_keys selects "continue" to exit its loop
        # 7. Main loop select chooses "continue" to break out
        with (
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                return_value="new-role",
            ),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(f"{_HELPERS}._configure_delegations_paths"),
            patch(
                f"{_HELPERS}._select",
                side_effect=["Add Keys", "continue", "continue"],
            ),
            patch(f"{_HELPERS}._threshold_prompt", return_value=1),
            patch(f"{_HELPERS}._configure_delegations_keys") as mock_conf_keys,
        ):

            result = helpers._configure_delegations()
            assert "new-role" in result.roles
            mock_conf_keys.assert_called_once()

    def test_configure_delegations_remove_empty_roles(self):
        """Test selecting 'remove delegation' when roles is None/empty."""
        mock_delegations_instance = MagicMock(spec=Delegations)
        mock_delegations_instance.keys = {}

        # Start with roles populated so the main loop presents the full menu
        # via _select
        mock_delegations_instance.roles = {"some-role": MagicMock()}

        def side_effect_delegations(*args, **kwargs):
            return mock_delegations_instance

        # Sequence for _select:
        # 1. First iteration: returns "remove delegation"
        # 2. Inside "remove delegation", we want it to hit
        #  `if delegations.roles is None:`
        #    so we change it to None right before it checks.
        # 3. Second iteration: returns "continue" to break the main loop.
        def mock_select_side_effect(choices):
            # When it prompts for removal, simulate roles being None
            mock_delegations_instance.roles = None
            return "remove delegation"

        with (
            patch(
                f"{_HELPERS}._select",
                side_effect=[mock_select_side_effect, "continue"],
            ),
            patch(
                f"{_HELPERS}.Delegations", side_effect=side_effect_delegations
            ),
            patch(f"{_HELPERS}._print_delegation"),
        ):

            result = helpers._configure_delegations()
            assert result is mock_delegations_instance

    def test_configure_delegations_overwrite_decline(self):
        """Test declining to overwrite an existing delegation."""
        existing_role = DelegatedRole(
            name="existing-role",
            keyids=[],
            threshold=1,
            terminating=True,
            paths=[],
        )
        delegations = Delegations(
            keys={}, roles={"existing-role": existing_role}
        )

        def select_side_effect(choices):
            if "continue" in choices and "add new delegation" in choices:
                if not hasattr(select_side_effect, "called_main"):
                    select_side_effect.called_main = True
                    return "add new delegation"

                return "continue"
            elif "Online Key (use the existing)" in choices:
                return "Online Key (use the existing)"
            return "continue"

        with (
            patch(f"{_HELPERS}.Delegations", return_value=delegations),
            patch(f"{_HELPERS}._print_delegation"),
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                return_value="existing-role",
            ),
            patch("rich.prompt.Confirm.ask", return_value=False),
            patch(f"{_HELPERS}._select", side_effect=select_side_effect),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(f"{_HELPERS}._configure_delegations_paths"),
        ):

            result = helpers._configure_delegations()
            assert result is delegations

    def test_configure_delegations_remove_role_with_unused_key(self):
        """Test removing a delegation that owns an unused key."""
        key_id = "unique-key-id"
        mock_key = MagicMock()

        removed_role = DelegatedRole(
            name="role-to-remove",
            keyids=[key_id],
            threshold=1,
            terminating=True,
            paths=[],
        )
        other_role = DelegatedRole(
            name="other-role",
            keyids=[],
            threshold=1,
            terminating=True,
            paths=[],
        )

        delegations = Delegations(
            keys={key_id: mock_key},
            roles={"role-to-remove": removed_role, "other-role": other_role},
        )

        with (
            patch(f"{_HELPERS}.Delegations", return_value=delegations),
            patch(f"{_HELPERS}._print_delegation"),
            patch(
                f"{_HELPERS}._select",
                side_effect=[
                    "remove delegation",
                    "role-to-remove",
                    "continue",
                ],
            ),
        ):

            result = helpers._configure_delegations()
            # Verify the unique key was popped from delegations.keys
            assert key_id not in result.keys

    def test__configure_delegations_add_delegation(self, ed25519_key):
        with (
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                return_value="myrole",
            ),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(
                f"{_HELPERS}._configure_delegations_paths",
                side_effect=lambda dr: dr,
            ),
            patch(
                f"{_HELPERS}._select",
                side_effect=["Online Key (use the existing)", "continue"],
            ),
        ):
            result = helpers._configure_delegations()

        assert "myrole" in result.roles

    def test__configure_delegations_add_two_remove_one(self):
        # Add role1 (forced), add role2, remove role1, continue
        with (
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                side_effect=["role1", "role2"],
            ),
            patch(
                f"{_HELPERS}._expiry_prompt",
                side_effect=[(30, None), (30, None)],
            ),
            patch(
                f"{_HELPERS}._configure_delegations_paths",
                side_effect=lambda dr: dr,
            ),
            patch(
                f"{_HELPERS}._select",
                side_effect=[
                    "Online Key (use the existing)",  # signing for role1
                    "add new delegation",  # main loop
                    "Online Key (use the existing)",  # signing for role2
                    "remove delegation",  # main loop
                    "role1",  # which role to remove
                    "continue",  # main loop
                ],
            ),
        ):
            result = helpers._configure_delegations()

        assert "role1" not in result.roles
        assert "role2" in result.roles

    def test__configure_delegations_duplicate_name_overwrite(
        self, ed25519_key
    ):
        with (
            patch(
                f"{_HELPERS}._delegated_target_role_name_prompt",
                return_value="myrole",
            ),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(
                f"{_HELPERS}._configure_delegations_paths",
                side_effect=lambda dr: dr,
            ),
            patch(
                f"{_HELPERS}._select",
                side_effect=[
                    "Online Key (use the existing)",
                    "add new delegation",
                    "Online Key (use the existing)",
                    "continue",
                ],
            ),
            patch(f"{_HELPERS}.Confirm.ask", return_value=True),
        ):
            result = helpers._configure_delegations()

        assert "myrole" in result.roles

    def test_configure_delegations_prompt_bins(self, monkeypatch):
        settings = helpers._Settings(1, 1, 365)
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *_: helpers.DELEGATIONS_TYPE.BINS,
        )
        monkeypatch.setattr(
            f"{_HELPERS}._expiry_prompt",
            lambda *_: (2, None),
        )
        monkeypatch.setattr(
            f"{_HELPERS}.IntPrompt.ask",
            lambda *a, **kw: 256,
        )

        helpers._configure_delegations_prompt(settings)

        assert settings.bins_expiry == 2
        assert settings.bins_number == 256

    def test_configure_delegations_prompt_custom(self, monkeypatch):
        settings = helpers._Settings(1, 1, 365)
        fake_delegations = Delegations(keys={}, roles={})
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *_: helpers.DELEGATIONS_TYPE.CUSTOM_DELEGATIONS,
        )
        monkeypatch.setattr(
            f"{_HELPERS}._configure_delegations",
            lambda: fake_delegations,
        )

        helpers._configure_delegations_prompt(settings)

        assert settings.delegations == fake_delegations

    def test_configure_delegations_prompt_none_selection(self):
        """Test _configure_delegations_prompt when _select returns None
        first"""
        settings = MagicMock()

        with (
            patch(
                f"{_HELPERS}._select",
                side_effect=[None, helpers.DELEGATIONS_TYPE.BINS],
            ),
            patch(f"{_HELPERS}._expiry_prompt", return_value=(30, None)),
            patch(f"{_HELPERS}.IntPrompt.ask", return_value=8),
            patch(f"{_HELPERS}.console.print"),
        ):

            helpers._configure_delegations_prompt(settings)
            assert settings.bins_expiry == 30
            assert settings.bins_number == 8

    def test_print_targets(self):
        targets = Metadata(
            Targets(
                targets={
                    "test_file": TargetFile(
                        length=10,
                        hashes={"sha256": "abc"},
                        path="test_file",
                    )
                }
            )
        )
        # Verify it runs without error
        helpers._print_targets(targets)

    def test_print_delegation(self, ed25519_key):
        # Case 1: delegations.roles is None
        empty_delegations = Delegations(
            keys={},
            succinct_roles=SuccinctRoles(
                keyids=[], threshold=1, bit_length=16, name_prefix="bin-"
            ),
        )
        assert helpers._print_delegation(empty_delegations) is None

        # Case 2: delegation with key and delegation without key (online)
        role1 = DelegatedRole(
            name="role1",
            keyids=[ed25519_key.keyid],
            threshold=1,
            terminating=False,
            paths=["a/*"],
            unrecognized_fields={"x-rstuf-expire-policy": "30"},
        )
        role2 = DelegatedRole(
            name="role2",
            keyids=[],
            threshold=1,
            terminating=False,
            path_hash_prefixes=["prefix/"],
            unrecognized_fields={"x-rstuf-expire-policy": "60"},
        )
        ed25519_key.unrecognized_fields[helpers.KEY_NAME_FIELD] = "my_key"
        delegations = Delegations(
            keys={ed25519_key.keyid: ed25519_key},
            roles={"role1": role1, "role2": role2},
        )
        helpers._print_delegation(delegations)

    def test_print_missing_key_info(self):
        helpers._print_missing_key_info(2, 1)
        helpers._print_missing_key_info(3, 2)
        helpers._print_missing_key_info(2, 0)

    def test_warn_no_save(self):
        helpers._warn_no_save()
