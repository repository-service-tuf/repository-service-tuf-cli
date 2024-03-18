import json
from copy import copy
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pretend import call, call_recorder, stub
from securesystemslib.signer import CryptoSigner, Key, SSlibKey
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin2 import helpers
from repository_service_tuf.cli.admin2.ceremony import ceremony
from repository_service_tuf.cli.admin2.sign import sign
from repository_service_tuf.cli.admin2.update import update

_FILES = Path(__file__).parent.parent.parent / "files"
_ROOTS = _FILES / "root"
_PEMS = _FILES / "pem"
_PAYLOADS = _FILES / "payload"

_PROMPT = "rich.console.Console.input"
_HELPERS = "repository_service_tuf.cli.admin2.helpers"


@pytest.fixture
def patch_getpass(monkeypatch):
    """Fixture to mock password prompt return value for encrypted test keys.

    NOTE: we need this, because getpass does not receive the inputs passed to
    click's invoke method (interestingly, click's own password prompt, which
    also uses getpass, does receive them)
    """

    def mock_getpass(prompt, stream=None):
        # no need to mock prompt output, rich prompts independently
        return "hunter2"

    monkeypatch.setattr("rich.console.getpass", mock_getpass)


@pytest.fixture
def patch_utcnow(monkeypatch):
    """Patch `utcnow` in helpers module for reproducible results."""

    class FakeTime(datetime):
        @classmethod
        def utcnow(cls):
            return datetime(2024, 1, 1, 0, 0, 0)

    monkeypatch.setattr(f"{_HELPERS}.datetime", FakeTime)


@pytest.fixture
def ed25519_key():
    with open(f"{_PEMS / 'ed25519.pub'}", "rb") as f:
        public_pem = f.read()
    public_key = load_pem_public_key(public_pem)
    return SSlibKey.from_crypto(public_key, "fake_keyid")


@pytest.fixture
def ed25519_signer(ed25519_key):
    with open(f"{_PEMS / 'ed25519'}", "rb") as f:
        private_pem = f.read()

    private_key = load_pem_private_key(private_pem, b"hunter2")
    return CryptoSigner(private_key, ed25519_key)


# flake8: noqa


class TestCLI:

    @staticmethod
    def _invoke(client, cmd, inputs, args):
        """Invoke cli command and return content of `-s <output>` result."""
        out_fn = "out"
        with client.isolated_filesystem():
            client.invoke(
                cmd,
                args=args + ["-s", out_fn],
                input="\n".join(inputs),
                catch_exceptions=False,
            )
            with open(out_fn) as f:
                result = json.load(f)

        return result

    def test_ceremony(self, client, patch_getpass, patch_utcnow):
        inputs = [
            "",  # Please enter days until expiry for root role (365)
            "",  # Please enter days until expiry for timestamp role (1)
            "",  # Please enter days until expiry for snapshot role (1)
            "",  # Please enter days until expiry for targets role (365)
            "",  # Please enter days until expiry for bins role (1)
            "",  # Please enter number of delegated hash bins [2/4/8/16/32/64/128/256/512/1024/2048/4096/8192/16384] (256)
            "2",  # Please enter root threshold
            f"{_PEMS / 'rsa.pub'}",  # Please enter path to public key
            "my rsa key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index
            f"{_PEMS / 'ecdsa.pub'}",  #  Please enter path to public key
            "my ec key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue
            f"{_PEMS / 'ed25519.pub'}",  #  Please enter path to public key
            "my ed key",  # Please enter key name
            "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue
            f"{_PEMS / 'rsa.pub'}",  #  Please enter path to public key
            "my rsa online key",  # Please enter a key name
            "2",  # Please enter signing key index
            f"{_PEMS / 'ed25519'}",  # Please enter path to encrypted private key
            "1",  # Please enter signing key index
            f"{_PEMS / 'ecdsa'}",  # Please enter path to encrypted private key
        ]

        result = self._invoke(client, ceremony, inputs, [])

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result == expected

    def test_update(self, client, patch_getpass, patch_utcnow):
        inputs = [
            "",  # Please enter days until expiry for root role (365)
            "y",  # Do you want to change the threshold? [y/n] (n)
            "1",  # Please enter root threshold
            "2",  # Please press 0 to add key, or remove key by entering its index. Press enter to continue
            "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to continue
            f"{_PEMS / 'rsa.pub'}",  # Please enter path to public key
            "rsa root key",  # Please enter a key name
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to continue:
            "",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'ecdsa.pub'}",  # Please enter path to public key
            "my ecdsa online key",  # Please enter a key name
            "1",  # Please enter signing key index
            f"{_PEMS / 'ed25519'}",  # Please enter path to encrypted private key
            "1",  # Please enter signing key index
            f"{_PEMS / 'ecdsa'}",  # Please enter path to encrypted private key
            "1",  # Please enter signing key index
            f"{_PEMS / 'rsa'}",  # Please enter path to encrypted private key
        ]
        args = [f"{_ROOTS / 'v1.json'}"]

        result = self._invoke(client, update, inputs, args)
        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result == expected

    def test_sign(self, client, patch_getpass):
        inputs = [
            "4",  # Please enter signing key index
            f"{_PEMS / 'rsa'}",  # Please enter path to encrypted private key
        ]
        args = [
            f"{_ROOTS / 'v2.json'}",
            f"{_ROOTS / 'v1.json'}",
        ]
        result = self._invoke(client, sign, inputs, args)

        with open(_PAYLOADS / "sign.json") as f:
            expected = json.load(f)

        assert result["role"] == "root"
        assert result["signature"]["keyid"] == expected["signature"]["keyid"]


class TestHelpers:
    def test_load_signer_from_file_prompt(self, ed25519_key):
        # success
        inputs = [f"{_PEMS / 'ed25519'}", "hunter2"]
        with patch(_PROMPT, side_effect=inputs):
            signer = helpers._load_signer_from_file_prompt(ed25519_key)

        assert isinstance(signer, CryptoSigner)

        # fail with wrong file for key
        inputs = [f"{_PEMS / 'rsa'}", "hunter2"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

        # fail with bad password
        inputs = [f"{_PEMS / 'ed25519'}", "hunter1"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_signer_from_file_prompt(ed25519_key)

    def test_load_key_from_file_prompt(self):
        # success
        inputs = [f"{_PEMS / 'ed25519.pub'}"]
        with patch(_PROMPT, side_effect=inputs):
            key = helpers._load_key_from_file_prompt()

        assert isinstance(key, SSlibKey)

        # fail with wrong file
        inputs = [f"{_PEMS / 'ed25519'}"]
        with patch(_PROMPT, side_effect=inputs):
            with pytest.raises(ValueError):
                signer = helpers._load_key_from_file_prompt()

    def test_load_key_prompt(self):
        fake_root = stub(keys={"123"})

        # return key
        fake_key = stub(keyid="abc")
        with patch(
            f"{_HELPERS}._load_key_from_file_prompt", return_value=fake_key
        ):
            key = helpers._load_key_prompt(fake_root)

        assert key == fake_key

        # return None - key in use
        fake_key = stub(keyid="123")
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
        fake_key = stub(unrecognized_fields={helpers.KEY_NAME_FIELD: "taken"})
        fake_root = stub(keys={"fake_key": fake_key})

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

        assert result == (
            days_input,
            datetime(2024, 1, 11, 0, 0, 0),  # see patch_utcnow
        )

        # Assert bump per-role default expiry
        for role in ["root", "timestamp", "snapshot", "targets", "bins"]:
            expected_days = getattr(helpers.ExpirationSettings, role)
            days_input = ""
            with patch(_PROMPT, side_effect=[days_input]):
                days, _ = helpers._expiry_prompt(role)

            assert days == expected_days

    def test_expiration_settings_prompt(self, patch_utcnow):
        inputs = [""] * 5
        with patch(_PROMPT, side_effect=inputs):
            result = helpers._expiration_settings_prompt()

        # Assert default ExpirationSettings and default root expiration date
        assert result == (
            helpers.ExpirationSettings(),
            datetime(2024, 12, 31, 0, 0),
        )

    def test_service_settings_prompt(self):
        data = [
            (
                ("",),
                (helpers.ServiceSettings.number_of_delegated_bins,),
            ),
            (
                ("2",),
                (2,),
            ),
        ]
        for inputs, expected in data:
            with patch(_PROMPT, side_effect=inputs):
                result = helpers._service_settings_prompt()

            assert result == helpers.ServiceSettings(*expected)

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
        key2 = copy(ed25519_key)
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
        prev_root = stub()
        root_md = stub(
            signed=stub(),
            signed_bytes=stub(),
            signatures=stub(),
        )
        # Metadata fully verified (exit loop early)
        root_result = stub(verified=True)
        root_md.signed.get_root_verification_result = lambda *a: root_result
        helpers._add_root_signatures_prompt(root_md, prev_root)

        # Metadata not verified (run loop twice)
        # 1. choose key to sign (choose: 1)
        # 2. skip signing (choose: -1)
        root_result = stub(verified=False, signed=True)
        root_md.signed.get_root_verification_result = lambda *a: root_result
        keys = [ed25519_key]

        mock_add_sig = call_recorder(lambda root, key: None)

        with (
            patch(
                f"{_HELPERS}._filter_root_verification_results",
                return_value=stub(),
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

        assert mock_add_sig.calls == [call(root_md, ed25519_key)]

    def test_get_root_keys(self, ed25519_key):
        root = Root()
        ed25519_key2 = copy(ed25519_key)
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
            root_result = stub(
                first=stub(verified=verif1, missing=miss1, unsigned=unsig1),
                second=stub(verified=verif2, missing=miss2, unsigned=unsig2),
            )
            results = helpers._filter_root_verification_results(root_result)
            assert len(results) == len_, root_result

    def test_print_keys_for_signing(self, ed25519_key):
        ed25519_key2 = copy(ed25519_key)
        ed25519_key2.keyid = "fake_keyid2"
        results = [
            stub(missing=1, unsigned={ed25519_key.keyid: ed25519_key}),
            stub(missing=1, unsigned={ed25519_key2.keyid: ed25519_key2}),
        ]
        keys = helpers._print_keys_for_signing(results)
        assert keys == [ed25519_key, ed25519_key2]

    def test_print_root_keys(self, ed25519_key):
        ed25519_key2 = copy(ed25519_key)
        ed25519_key2.keyid = "fake_keyid2"
        root = Root()
        root.add_key(ed25519_key, "root")
        root.add_key(ed25519_key2, "root")
        keys = helpers._print_root_keys(root)
        assert keys == [ed25519_key, ed25519_key2]
