# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import copy
import json
import unittest.mock
from datetime import datetime, timedelta
from typing import Dict, List

import pretend
import pytest
from securesystemslib.signer import SSlibKey as Key  # type: ignore
from tuf.api.exceptions import UnsignedMetadataError

from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers import tuf
from repository_service_tuf.helpers.tuf import (
    Metadata,
    MetadataInfo,
    Roles,
    Root,
    RSTUFKey,
    TUFManagement,
    load_key,
)


class TestRSTUFKey:
    def test__eq__(self):
        key = RSTUFKey({"keyid": "123456789a", "keyval": {"sha256": "abc"}})
        copy_key = copy.deepcopy(key)
        assert key == copy_key
        # Change copy_key keyid and verify they are not equal
        copy_key.key["keyid"] = "foo"
        assert key != copy_key
        assert key != ""


class TestTUFHelperFunctions:
    def test__conform_rsa_in_aws_format(self):
        pub_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArrJWZ7ieuDiQTlKVcCNx1/pT+8jN1BOMM2xM511Hp1TBi09pSgqsw9pS/o8oV24Q2Q9ebjbKIwqjhTZYLnKOUk4pKMgL56MvqXJLTUvR+9IC1vPuEURUGBjZqew7A11BbdII3BJVVH/F9rKvgiDLZ9WzM5rZGzQi4L52u4Gb3uSLF0QEXBx7i58DF7zs34GpZqgseKN0Q6kb8Vp4VcoDWeW+OCbWNIJd0Bas7ojUi9IosUlJJNE5f2UxqDCNwtf6PiEcYfulU3zIpO3rAuVJ/iKzBMQ61FtsaUd3M4kjsozoAEK3WSqW+RtuYVj5Rr0HYUFB2QXOsDVzIdZ7GLicXQIDAQAB"  # noqa
        result = tuf._conform_rsa_key(pub_key)
        expected_result = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArrJWZ7ieuDiQTlKVcCNx\n1/pT+8jN1BOMM2xM511Hp1TBi09pSgqsw9pS/o8oV24Q2Q9ebjbKIwqjhTZYLnKO\nUk4pKMgL56MvqXJLTUvR+9IC1vPuEURUGBjZqew7A11BbdII3BJVVH/F9rKvgiDL\nZ9WzM5rZGzQi4L52u4Gb3uSLF0QEXBx7i58DF7zs34GpZqgseKN0Q6kb8Vp4VcoD\nWeW+OCbWNIJd0Bas7ojUi9IosUlJJNE5f2UxqDCNwtf6PiEcYfulU3zIpO3rAuVJ\n/iKzBMQ61FtsaUd3M4kjsozoAEK3WSqW+RtuYVj5Rr0HYUFB2QXOsDVzIdZ7GLic\nXQIDAQAB\n-----END PUBLIC KEY-----\n"  # noqa
        assert result == expected_result

    def test__conform_rsa_key_already_correct_format(self):
        pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxcpCDgsz+2pIbvOHte1k\nnC78oeiKACUuo4/0QBwOg+SB6gIh36OEPo0snoxqMDRk4DwksHxCw02jUlWIc1qp\nACvTtpBNk1zD+akbBTpqmBIiZrnf3n2MbiZUdS0DxpHFUhrAsalf60Wzeb9K5cIK\nQJwGCM/TdoZWFGnll6hkpgbK2bl+68oBmvSyL6Gpu66EbmnVGbdKk6CzQzVLq2AD\nkVHaCLvMO4xIT+BzeqNY5FLV6/aa2pxkNPl/lupbkg/lopIdNRCRUSNvKMGEu47L\nVc1iCP1MuV62jhbhqXuzlAEfT6KPFH/drrOfJhWIIdkvdnsNDJuN7eJ637gwiqNe\nDwIDAQAB\n-----END PUBLIC KEY-----\n"  # noqa
        result = tuf._conform_rsa_key(pub_key)
        assert result == pub_key

    def test_load_key(self, monkeypatch):
        monkeypatch.setattr(
            tuf,
            "import_privatekey_from_file",
            pretend.call_recorder(lambda *a: {"keyid": "ema"}),
        )

        result = load_key(
            "/p/key", KeyType.KEY_TYPE_ED25519.value, "pwd", None
        )
        assert result == RSTUFKey({"keyid": "ema"}, "/p/key", None)
        assert tuf.import_privatekey_from_file.calls == [
            pretend.call("/p/key", KeyType.KEY_TYPE_ED25519.value, "pwd")
        ]

    def test_load_key_CryptoError(self, monkeypatch):
        monkeypatch.setattr(
            tuf,
            "import_privatekey_from_file",
            pretend.raiser(tuf.CryptoError("wrong password")),
        )

        result = load_key(
            "/p/key", KeyType.KEY_TYPE_ED25519.value, "pwd", None
        )
        assert result == tuf.RSTUFKey(
            {},
            None,
            error=(
                ":cross_mark: [red]Failed[/]: wrong password Check the "
                "password, type, etc"
            ),
        )

    def test_load_key_OSError(self, monkeypatch):
        monkeypatch.setattr(
            tuf,
            "import_privatekey_from_file",
            pretend.raiser(OSError("permission denied")),
        )
        result = load_key(
            "/p/key", KeyType.KEY_TYPE_ED25519.value, "pwd", None
        )
        assert result == RSTUFKey(
            {}, None, error=":cross_mark: [red]Failed[/]: permission denied"
        )

    def test_load_payload(self, monkeypatch):
        fake_data = [
            pretend.stub(read=pretend.call_recorder(lambda: b"{'k': 'v'}"))
        ]
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: fake_data),
        )
        monkeypatch.setitem(tuf.__builtins__, "open", lambda *a: fake_file_obj)
        tuf.json.load = pretend.call_recorder(lambda *a: {"k": "v"})

        result = tuf.load_payload("new_file")
        assert result == {"k": "v"}
        assert tuf.json.load.calls == [pretend.call(fake_data)]

    def test_load_payload_OSError(self, monkeypatch):
        monkeypatch.setitem(
            tuf.__builtins__,
            "open",
            pretend.raiser(FileNotFoundError("payload.json not found")),
        )
        with pytest.raises(tuf.click.ClickException) as err:
            tuf.load_payload("payload.json")

        assert "Error to load payload.json" in str(err)
        assert "payload.json not found" in str(err)

    def test_save_payload(self, monkeypatch):
        fake_data = pretend.stub(
            write=pretend.call_recorder(lambda *a: "{'k': 'v'}")
        )
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            write=pretend.call_recorder(lambda: fake_data),
        )
        fake_open = pretend.call_recorder(lambda *a: fake_file_obj)
        monkeypatch.setitem(tuf.__builtins__, "open", fake_open)
        monkeypatch.setattr(
            tuf.json,
            "dumps",
            pretend.call_recorder(lambda *a, **kw: "{'k': 'v'}"),
        )

        result = tuf.save_payload("new_file", {"k": "v"})
        assert result is None
        assert tuf.json.dumps.calls == [pretend.call({"k": "v"}, indent=2)]
        assert fake_open.calls == [pretend.call("new_file.json", "w")]

    def test_save_payload_file_with_json_suffix(self, monkeypatch):
        fake_data = pretend.stub(
            write=pretend.call_recorder(lambda *a: "{'k': 'v'}")
        )
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            write=pretend.call_recorder(lambda: fake_data),
        )
        fake_open = pretend.call_recorder(lambda *a: fake_file_obj)
        monkeypatch.setitem(tuf.__builtins__, "open", fake_open)
        monkeypatch.setattr(
            tuf.json,
            "dumps",
            pretend.call_recorder(lambda *a, **kw: "{'k': 'v'}"),
        )

        result = tuf.save_payload("new_file.json", {"k": "v"})
        assert result is None
        assert tuf.json.dumps.calls == [pretend.call({"k": "v"}, indent=2)]
        assert fake_open.calls == [pretend.call("new_file.json", "w")]

    def test_save_payload_OSError(self, monkeypatch):
        monkeypatch.setitem(
            tuf.__builtins__,
            "open",
            pretend.raiser(PermissionError("permission denied")),
        )
        with pytest.raises(tuf.click.ClickException) as err:
            tuf.save_payload("payload.json", {"k": "v"})

        assert "Failed to save payload.json" in str(err)
        assert "permission denied" in str(err)


class TestMetadataInfo:
    def test__init(self, root: Metadata[Root]):
        root_info = MetadataInfo(root)
        assert root_info._new_md == root
        assert root_info.signing_keys == {}
        # Check that root_info._trusted_md is a copy of root
        assert root_info._trusted_md is not root
        assert root_info._trusted_md == root

    def test__get_key_name_with_custom_name(self):
        key = Key("id", "ed25519", "", {"sha256": "abc"}, {"name": "my_key"})
        name = MetadataInfo._get_key_name(key)
        assert name == "my_key"

    def test__get_key_name_without_custom_name(self):
        key = Key("123456789a", "ed25519", "", {"sha256": "abc"})
        name = MetadataInfo._get_key_name(key)
        assert name == "1234567"

    def test__get_key_name_with_empty_string_name(self):
        key = Key("123456789a", "ed25519", "", {"sha256": "abc"}, {"name": ""})
        name = MetadataInfo._get_key_name(key)
        assert name == "1234567"

    def test__get_pending_and_used_keys(self):
        with open("tests/files/das-root.json", "r") as f:
            das_root = json.loads(f.read())

        md_info = MetadataInfo(Metadata.from_dict(das_root["root"]))
        used_keys_info, pending_keys = md_info._get_pending_and_used_keys()
        assert len(used_keys_info) == 1
        assert used_keys_info[0] == {
            "keyid": "1cebe343e35f0213f6136758e6c3a8f8e1f9eeb7e47a07d5cb336462ed31dcb7",  # noqa
            "name": "Janis Joplin",
            "keytype": "ed25519",
            "keyval": {
                "public": "ad1709b3cb419b99c5cd7427d6411522e5a93aec6767453e91af921a73d22a3c",  # noqa
            },
            "scheme": "ed25519",
        }
        assert len(pending_keys) == 1
        assert pending_keys[0] == {
            "keyid": "800dfb5a1982b82b7893e58035e19f414f553fc08cbb1130cfbae302a7b7fee5",  # noqa
            "name": "Jimi Hendrix",
            "keytype": "ed25519",
            "keyval": {
                "public": "7098f769f6ab8502b50f3b58686b8a042d5d3bb75d8b3a48a2fcbc15a0223501",  # noqa
            },
            "scheme": "ed25519",
        }

    def test_is_keyid_used_true(self, root: Metadata[Root]):
        root.signed.add_key(Key("id", "ed25519", "", {"sha256": "ab"}), "root")
        root.signed.add_key(Key("id2", "ed25519", "", {}), "timestamp")
        root_info = MetadataInfo(root)
        assert root_info.is_keyid_used("id") is True

    def test_is_keyid_used_false(self, root: Metadata[Root]):
        root.signed.add_key(Key("id2", "ed25519", "", {}), "timestamp")
        root_info = MetadataInfo(root)
        assert root_info.is_keyid_used("id") is False

    def test_save_current_md_key(self, root_info: MetadataInfo):
        tuf_key: Key = root_info._new_md.signed.keys["id1"]
        key_dict = {**tuf_key.to_dict(), "keyid": tuf_key.keyid}
        key = RSTUFKey(key_dict)
        root_info.save_current_md_key(key)
        assert root_info.signing_keys == {"id1": key}

    def test_remove_key_existing(self, root_info: MetadataInfo):
        # Assert key with name "id1" exists before the removal
        assert len(root_info.keys) == 2
        assert root_info._new_md.signed.keys.get("id1") is not None
        assert "id1" in root_info._new_md.signed.roles["root"].keyids

        assert root_info.remove_key("id1") is True

        assert len(root_info.keys) == 1
        # Assert key was actually removed from root metadata
        assert root_info._new_md.signed.keys.get("id1") is None
        assert "id1" not in root_info._new_md.signed.roles["root"].keyids

    def test_remove_key_non_existing(self, root_info: MetadataInfo):
        assert "BAD_ID" not in root_info._new_md.signed.roles["root"].keyids
        assert len(root_info.keys) == 2
        assert root_info.remove_key("BAD_ID") is False
        assert len(root_info.keys) == 2

    def test_new_signing_keys_required_threshold_fulfilled(
        self, root_info: MetadataInfo
    ):
        root_info._new_md.signed.roles["root"].threshold = 1
        for keyid in root_info._new_md.signed.roles["root"].keyids:
            root_info.signing_keys[keyid] = "b"

        assert root_info.new_signing_keys_required() == 0

    def test_new_signing_keys_required_threshold_not_fulfilled(
        self, root_info: MetadataInfo
    ):
        root_info._new_md.signed.roles["root"].threshold = 10
        for keyid in root_info._new_md.signed.roles["root"].keyids:
            root_info.signing_keys[keyid] = "b"

        assert root_info.new_signing_keys_required() == 8

    def test_add_key(self, root_info: MetadataInfo):
        dict = {"keyid": "123", "keyval": {"sha256": "abc"}}
        key = RSTUFKey(dict, name="custom_name")
        tuf.Key.from_securesystemslib_key = pretend.call_recorder(
            lambda *a: Key("123", "", "", {"sha256": "abc"})
        )
        # Assert that key didn't existed before
        assert len(root_info.keys) == 2
        assert "123" not in root_info._new_md.signed.roles["root"].keyids

        root_info.add_key(key)

        assert len(root_info.keys) == 3
        assert "123" in root_info._new_md.signed.roles["root"].keyids
        assert tuf.Key.from_securesystemslib_key.calls == [pretend.call(dict)]

    def test_add_key_without_name(self, root_info: MetadataInfo):
        dict = {"keyid": "123", "keyval": {"sha256": "abc"}}
        key = RSTUFKey(dict)
        tuf.Key.from_securesystemslib_key = pretend.call_recorder(
            lambda *a: Key("123", "", "", {"sha256": "abc"})
        )
        # Assert that key didn't existed before
        assert len(root_info.keys) == 2
        assert "123" not in root_info._new_md.signed.roles["root"].keyids

        root_info.add_key(key)

        assert len(root_info.keys) == 3
        assert "123" in root_info._new_md.signed.roles["root"].keyids
        new_key = root_info._new_md.signed.keys["123"]
        # Assert no "name" was added
        assert new_key.unrecognized_fields.get("name") is None
        assert tuf.Key.from_securesystemslib_key.calls == [pretend.call(dict)]

    def test_change_online_key(self, root_info: MetadataInfo):
        # The id of the current online key.
        key_id = root_info._new_md.signed.roles["timestamp"].keyids[0]
        new_key_id = "id4"
        tuf.Key.from_securesystemslib_key = pretend.call_recorder(
            lambda *a: Key(new_key_id, "", "", {"sha256": "abc"})
        )
        dict = {"keyid": new_key_id, "keyval": {"sha256": "abc"}}
        new_key = RSTUFKey(dict, name="custom_name")
        root_info.change_online_key(new_key)
        for role in ["timestamp", "snapshot", "targets"]:
            assert new_key_id in root_info._new_md.signed.roles[role].keyids
            assert key_id not in root_info._new_md.signed.roles[role].keyids

        assert root_info.online_key["name"] == "custom_name"
        assert tuf.Key.from_securesystemslib_key.calls == [pretend.call(dict)]

    def test_has_changed(self, root_info: MetadataInfo):
        assert root_info.has_changed() is False
        root_info._new_md.signed.version += 1
        assert root_info.has_changed() is True

    def test_get_signer(self, monkeypatch, root_info: MetadataInfo):
        rstuf_key = RSTUFKey(key={"fake": "key"}, key_path="fake_path")
        SSlibSigner = pretend.call_recorder(lambda *a: "FakeSSlibSigner")
        monkeypatch.setattr(
            "repository_service_tuf.helpers.tuf.SSlibSigner", SSlibSigner
        )
        result = root_info.get_signer(rstuf_key)

        assert result == "FakeSSlibSigner"
        assert SSlibSigner.calls == [pretend.call(rstuf_key.key)]

    def test_generate_payload(self, root_info: MetadataInfo):
        for key in root_info.keys:
            root_info.signing_keys[key["keyid"]] = RSTUFKey(key)

        signing_keys = list(root_info.signing_keys.values())
        signers_mock = unittest.mock.Mock()
        signers_mock.side_effect = ["signer1", "signer2"]
        tuf.SSlibSigner = signers_mock
        root_info._new_md.sign = pretend.call_recorder(lambda *a, **kw: None)
        root_info._trusted_md.verify_delegate = pretend.call_recorder(
            lambda *a: None
        )
        root_info._new_md.verify_delegate = pretend.call_recorder(
            lambda *a: None
        )
        tuf.console.print = pretend.call_recorder(lambda *a: None)

        result = root_info.generate_payload()
        assert result == {"metadata": {"root": root_info._new_md.to_dict()}}
        assert root_info._new_md.sign.calls == [
            pretend.call("signer1", append=True),
            pretend.call("signer2", append=True),
        ]
        assert root_info._trusted_md.verify_delegate.calls == [
            pretend.call(Root.type, root_info._new_md)
        ]
        assert root_info._new_md.verify_delegate.calls == [
            pretend.call(Root.type, root_info._new_md)
        ]
        assert tuf.console.print.calls == [
            pretend.call("\nVerifying the new payload..."),
            pretend.call("The new payload is [green]verified[/]"),
        ]
        signers_mock.assert_has_calls(
            [
                unittest.mock.call(signing_keys[0].key),
                unittest.mock.call(signing_keys[1].key),
            ]
        )

    def test_generate_payload_with_new_keys_added(
        self, root_info: MetadataInfo
    ):
        for key in root_info.keys:
            root_info.signing_keys[key["keyid"]] = RSTUFKey(key)

        signing_keys = list(root_info.signing_keys.values())
        # Add new key which is not part of current root meaning it's a key
        # added by the user.
        new_key = Key("id3", "ed25519", "ed25519", {"sha256": "boo"})
        root_info._new_md.signed.add_key(new_key, "root")
        new_rstuf_key = RSTUFKey(new_key.to_securesystemslib_key())
        root_info.signing_keys["id3"] = new_rstuf_key

        signers_mock = unittest.mock.Mock()
        signers_mock.side_effect = ["signer0", "signer1", "signer2"]
        tuf.SSlibSigner = signers_mock
        root_info._new_md.sign = pretend.call_recorder(lambda *a, **kw: None)
        root_info._trusted_md.verify_delegate = pretend.call_recorder(
            lambda *a: None
        )
        root_info._new_md.verify_delegate = pretend.call_recorder(
            lambda *a: None
        )
        tuf.console.print = pretend.call_recorder(lambda *a: None)

        result = root_info.generate_payload()
        assert result == {"metadata": {"root": root_info._new_md.to_dict()}}
        assert root_info._new_md.sign.calls == [
            pretend.call("signer0", append=True),
            pretend.call("signer1", append=True),
            pretend.call("signer2", append=True),
        ]
        assert root_info._trusted_md.verify_delegate.calls == [
            pretend.call(Root.type, root_info._new_md)
        ]
        assert root_info._new_md.verify_delegate.calls == [
            pretend.call(Root.type, root_info._new_md)
        ]
        assert tuf.console.print.calls == [
            pretend.call("\nVerifying the new payload..."),
            pretend.call("The new payload is [green]verified[/]"),
        ]
        signers_mock.assert_has_calls(
            [
                unittest.mock.call(signing_keys[0].key),
                unittest.mock.call(signing_keys[1].key),
                unittest.mock.call(new_rstuf_key.key),
            ]
        )

    def test_generate_payload_not_enough_current_md_keys(
        self, root_info: MetadataInfo
    ):
        root_info.signing_keys.clear()
        # If we don't copy we would see strange behavior as we are iterating
        # over the same list we are removing from
        keyids = copy.copy(root_info._trusted_md.signed.roles["root"].keyids)
        for id in keyids:
            root_info._trusted_md.signed.revoke_key(id, "root")

        # root_info._trusted_md.signed.roles["root"]
        root_info._trusted_md.verify_delegate = pretend.raiser(
            UnsignedMetadataError
        )
        tuf.console.print = pretend.call_recorder(lambda *a: None)

        with pytest.raises(tuf.click.ClickException) as err:
            root_info.generate_payload()

        e = "Not enough loaded keys left from current root: needed 1, have 0"
        assert e in str(err)
        assert tuf.console.print.calls == [
            pretend.call("\nVerifying the new payload..."),
        ]


class TestTUFManagement:
    def _setup_load(self, filenames: List[str]) -> Dict[str, str]:
        result = {}
        for filename in filenames:
            result[filename] = filename

        return result

    def test__signers_root_keys(self, test_tuf_management: TUFManagement):
        test_tuf_management.setup.root_keys = {
            "id1": RSTUFKey({"a": "b", "keyval": {"private": "foo"}}),
            "id2": RSTUFKey({"c": "d", "keyval": {"private": "foo"}}),
        }
        tuf.SSlibSigner = pretend.call_recorder(lambda *a: None)
        result = test_tuf_management._signers(Roles.ROOT)
        assert result == [None, None]
        assert tuf.SSlibSigner.calls == [
            pretend.call({"a": "b", "keyval": {"private": "foo"}}),
            pretend.call({"c": "d", "keyval": {"private": "foo"}}),
        ]

    def test__signers_other_role(self, test_tuf_management: TUFManagement):
        result = test_tuf_management._signers(Roles.TIMESTAMP)
        assert result == []

    def test__sign(self, test_tuf_management: TUFManagement):
        fake_role = pretend.stub(
            signatures=pretend.stub(
                clear=pretend.call_recorder(lambda *a: None)
            ),
            sign=pretend.call_recorder(lambda *a, **kw: None),
        )
        signer1 = pretend.stub(key_dict={"keyval": {"private": "signer1"}})
        signer2 = pretend.stub(key_dict={"keyval": {"private": None}})

        test_tuf_management._signers = pretend.call_recorder(
            lambda *a: [signer1, signer2]
        )

        result = test_tuf_management._sign(fake_role, "root")
        assert result is None
        assert fake_role.signatures.clear.calls == [pretend.call()]
        assert test_tuf_management._signers.calls == [pretend.call(Roles.ROOT)]
        assert fake_role.sign.calls == [
            pretend.call(signer1, append=True),
        ]

    def test__add_payload_root(self, test_tuf_management: TUFManagement):
        test_tuf_management.repository_metadata
        fake_role = pretend.stub()
        test_tuf_management._add_payload(fake_role, "root")
        assert test_tuf_management.repository_metadata["root"] == fake_role

    def test__add_payload_timestamp(self, test_tuf_management: TUFManagement):
        test_tuf_management.repository_metadata
        fake_role = pretend.stub()
        test_tuf_management._add_payload(fake_role, "timestamp")
        assert (
            test_tuf_management.repository_metadata["timestamp"] == fake_role
        )

    def test__add_payload_save(self, test_tuf_management: TUFManagement):
        fake_json_serializer = pretend.call_recorder(lambda *a: None)
        tuf.JSONSerializer = fake_json_serializer
        fake_role = pretend.stub(
            signed=pretend.stub(version=2),
            to_file=pretend.call_recorder(lambda *a: None),
        )
        test_tuf_management.save = True
        test_tuf_management._add_payload(fake_role, "root")
        assert test_tuf_management.repository_metadata["root"] == fake_role
        assert fake_json_serializer.calls == [pretend.call()]
        assert fake_role.to_file.calls == [
            pretend.call("metadata/2.root.json", None)
        ]

    def test__bump_expiry(
        self, monkeypatch, test_tuf_management: TUFManagement
    ):
        fake_role = pretend.stub(
            signed=pretend.stub(expires=0),
        )
        fake_time = datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf.helpers.tuf.datetime",
            fake_datetime,
        )
        test_tuf_management._bump_expiry(fake_role, "timestamp")
        assert fake_role.signed.expires == fake_time + timedelta(days=1)
        assert fake_datetime.now.calls == [pretend.call()]

    def test__validate_root_payload_exist(
        self, test_tuf_management: TUFManagement
    ):
        root_md = Metadata(Root())
        test_tuf_management.repository_metadata["root"] = root_md
        result = test_tuf_management._validate_root_payload_exist()

        assert result is None

    def test__validate_root_payload_exist_root_does_not_exist(
        self, test_tuf_management: TUFManagement
    ):
        with pytest.raises(ValueError) as err:
            test_tuf_management._validate_root_payload_exist()

        assert "Root is not initialized" in str(err)

    def test__validate_root_payload_exist_role_not_metadata_type(
        self, test_tuf_management: TUFManagement
    ):
        test_tuf_management.repository_metadata["root"] = ""

        with pytest.raises(ValueError) as err:
            test_tuf_management._validate_root_payload_exist()

        assert "Root is not initialized" in str(err)

    def test__verify_correct_keys_usage(
        self, test_tuf_management: TUFManagement
    ):
        fake_role_obj = pretend.stub(keyids=["keyid"])
        fake_root_role_obj = pretend.stub(keyids=["root_keyid"])
        fake_root = pretend.stub(
            roles={
                "timestamp": fake_role_obj,
                "snapshot": fake_role_obj,
                "targets": fake_role_obj,
                "root": fake_root_role_obj,
            }
        )
        result = test_tuf_management._verify_correct_keys_usage(fake_root)
        assert result is None

    def test__verify_correct_keys_usage_more_than_one_key(
        self, test_tuf_management: TUFManagement
    ):
        fake_role_obj = pretend.stub(keyids=["keyid1", "keyid2"])
        fake_root = pretend.stub(
            roles={
                "timestamp": fake_role_obj,
            }
        )
        with pytest.raises(ValueError) as err:
            test_tuf_management._verify_correct_keys_usage(fake_root)

        assert "Expected exactly one online key" in str(err)

    def test__verify_correct_keys_usage_different_keyids(
        self, test_tuf_management: TUFManagement
    ):
        fake_timestamp_role_obj = pretend.stub(keyids=["keyid"])
        fake_snapshot_role_obj = pretend.stub(keyids=["snapshot_keyid"])
        fake_root = pretend.stub(
            roles={
                "timestamp": fake_timestamp_role_obj,
                "snapshot": fake_snapshot_role_obj,
            }
        )
        with pytest.raises(ValueError) as err:
            test_tuf_management._verify_correct_keys_usage(fake_root)

        assert "keyid must be equal to the one used in timestamp" in str(err)

    def test__verify_correct_keys_usage_root_uses_online_key(
        self, test_tuf_management: TUFManagement
    ):
        fake_role_obj = pretend.stub(keyids=["keyid"])
        fake_root = pretend.stub(
            roles={
                "timestamp": fake_role_obj,
                "snapshot": fake_role_obj,
                "targets": fake_role_obj,
                "root": fake_role_obj,
            }
        )
        with pytest.raises(ValueError) as err:
            test_tuf_management._verify_correct_keys_usage(fake_root)

        assert "Root must not use the same key as timestamp" in str(err)

    def test__prepare_top_level_md_and_add_to_payload(
        self, test_tuf_management: TUFManagement
    ):
        fake_root = pretend.stub(
            signed=pretend.stub(
                type="root", add_key=pretend.call_recorder(lambda *a: None)
            ),
        )
        tuf.Root = pretend.call_recorder(lambda **kwargs: fake_root.signed)
        tuf.Metadata = pretend.call_recorder(lambda *a: fake_root)

        test_tuf_management._verify_correct_keys_usage = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._bump_expiry = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._sign = pretend.call_recorder(lambda *a: None)
        test_tuf_management._add_payload = pretend.call_recorder(
            lambda *a: None
        )
        add_key_args = {"role1": ["key1"], "role2": ["key2"]}

        test_tuf_management._prepare_root_and_add_it_to_payload(
            {}, add_key_args
        )
        assert tuf.Root.calls == [pretend.call(roles={})]
        assert tuf.Metadata.calls == [pretend.call(fake_root.signed)]
        assert fake_root.signed.add_key.calls == [
            pretend.call("key1", "role1"),
            pretend.call("key2", "role2"),
        ]
        assert test_tuf_management._verify_correct_keys_usage.calls == [
            pretend.call(fake_root.signed)
        ]
        assert test_tuf_management._bump_expiry.calls == [
            pretend.call(fake_root, "root"),
        ]
        assert test_tuf_management._sign.calls == [
            pretend.call(fake_root, "root"),
        ]
        assert test_tuf_management._add_payload.calls == [
            pretend.call(fake_root, "root"),
        ]

    def test_setup_key_name_root_key(self, test_tuf_management: TUFManagement):
        key = Key("id", "ed25519", "ed25519-sha256", {"sha256": "abc"})
        test_tuf_management.setup.root_keys["id"] = RSTUFKey({}, "", "my-key")
        test_tuf_management._setup_key_name(key, Roles.ROOT.value)
        assert key.unrecognized_fields["name"] == "my-key"

    def test_setup_key_name_root_key_no_key_name(
        self, test_tuf_management: TUFManagement
    ):
        key = Key("id", "ed25519", "ed25519-sha256", {"sha256": "abc"})
        test_tuf_management.setup.root_keys["id"] = RSTUFKey({}, "")
        test_tuf_management._setup_key_name(key, Roles.ROOT.value)
        assert key.unrecognized_fields == {}

    def test_setup_key_name_online_key(
        self, test_tuf_management: TUFManagement
    ):
        key = Key("id", "ed25519", "ed25519-sha256", {"sha256": "abc"})
        test_tuf_management.setup.online_key = RSTUFKey(
            {"keyid": "id"}, "", "my-key"
        )
        test_tuf_management._setup_key_name(key, Roles.TIMESTAMP.value)
        assert key.unrecognized_fields["name"] == "my-key"

    def test_initialize_metadata(self, test_tuf_management: TUFManagement):
        public_keys_mock = unittest.mock.Mock()
        public_keys_mock.side_effect = [
            ["root"],
            ["timestamp"],
            ["snapshot"],
            ["targets"],
        ]
        test_tuf_management._public_keys = public_keys_mock
        tuf.Role = pretend.call_recorder(lambda *a: "role")

        key_from_securesystemslib_mock = pretend.call_recorder(
            lambda role_name: f"{role_name}_key"
        )

        tuf.Key.from_securesystemslib_key = key_from_securesystemslib_mock
        test_tuf_management._setup_key_name = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._prepare_root_and_add_it_to_payload = (
            pretend.call_recorder(lambda *a: None)
        )
        test_tuf_management._validate_root_payload_exist = (
            pretend.call_recorder(lambda *a: None)
        )
        result = test_tuf_management.initialize_metadata()

        assert result == test_tuf_management.repository_metadata
        public_keys_mock.assert_has_calls(
            [
                unittest.mock.call(Roles.ROOT),
                unittest.mock.call(Roles.TIMESTAMP),
                unittest.mock.call(Roles.SNAPSHOT),
                unittest.mock.call(Roles.TARGETS),
            ]
        )
        assert tuf.Key.from_securesystemslib_key.calls == [
            pretend.call("root"),
            pretend.call("timestamp"),
            pretend.call("snapshot"),
            pretend.call("targets"),
        ]
        assert test_tuf_management._setup_key_name.calls == [
            pretend.call("root_key", "root"),
            pretend.call("timestamp_key", "timestamp"),
            pretend.call("snapshot_key", "snapshot"),
            pretend.call("targets_key", "targets"),
        ]
        expected_roles: Dict[str, str] = {
            "root": "role",
            "timestamp": "role",
            "snapshot": "role",
            "targets": "role",
        }
        expected_add_key_args: Dict[str, List[str]] = {
            "root": ["root_key"],
            "timestamp": ["timestamp_key"],
            "snapshot": ["snapshot_key"],
            "targets": ["targets_key"],
        }
        assert (
            test_tuf_management._prepare_root_and_add_it_to_payload.calls
            == [pretend.call(expected_roles, expected_add_key_args)]
        )
        assert test_tuf_management._validate_root_payload_exist.calls == [
            pretend.call()
        ]
