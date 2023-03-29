# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT

# from unittest.mock import Mock

import unittest.mock
from datetime import datetime, timedelta
from typing import Dict, List

import pretend
import pytest

from repository_service_tuf.helpers import tuf
from repository_service_tuf.helpers.tuf import (
    Metadata,
    Roles,
    Root,
    RSTUFKey,
    TUFManagement,
)


class TestTUFHelper:
    def _setup_load(self, filenames: List[str]) -> Dict[str, str]:
        result = {}
        for filename in filenames:
            result[filename] = filename

        return result

    def test__signers_root_keys(self, test_tuf_management: TUFManagement):
        test_tuf_management.setup.root_keys = [
            RSTUFKey({"a": "b"}),
            RSTUFKey({"c": "d"}),
        ]
        tuf.SSlibSigner = pretend.call_recorder(lambda *a: None)
        result = test_tuf_management._signers(Roles.ROOT)
        assert result == [None, None]
        assert tuf.SSlibSigner.calls == [
            pretend.call({"a": "b"}),
            pretend.call({"c": "d"}),
        ]

    def test__signers_online_key(self, test_tuf_management: TUFManagement):
        test_tuf_management.setup.online_key = RSTUFKey({"a": "b"})
        tuf.SSlibSigner = pretend.call_recorder(lambda *a: None)
        result = test_tuf_management._signers(Roles.TIMESTAMP)
        assert result == [None]
        assert tuf.SSlibSigner.calls == [
            pretend.call({"a": "b"}),
        ]

    def test__sign(self, test_tuf_management: TUFManagement):
        fake_role = pretend.stub(
            signatures=pretend.stub(
                clear=pretend.call_recorder(lambda *a: None)
            ),
            sign=pretend.call_recorder(lambda *a, **kw: None),
        )
        signers = ["signer1", "signer2"]
        test_tuf_management._signers = pretend.call_recorder(
            lambda *a: signers
        )

        result = test_tuf_management._sign(fake_role, "root")
        assert result is None
        assert fake_role.signatures.clear.calls == [pretend.call()]
        assert test_tuf_management._signers.calls == [pretend.call(Roles.ROOT)]
        assert fake_role.sign.calls == [
            pretend.call("signer1", append=True),
            pretend.call("signer2", append=True),
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

    def test_initialize_metadata(self, test_tuf_management: TUFManagement):
        signers_mock = unittest.mock.Mock()
        root_signer = pretend.stub(key_dict="root")
        timestamp_signer = pretend.stub(key_dict="timestamp")
        snapshot_signer = pretend.stub(key_dict="snapshot")
        targets_signer = pretend.stub(key_dict="targets")
        signers_mock.side_effect = [
            [root_signer],
            [timestamp_signer],
            [snapshot_signer],
            [targets_signer],
        ]
        test_tuf_management._signers = signers_mock
        tuf.Role = pretend.call_recorder(lambda *a: "role")

        key_from_securesystemslib_mock = pretend.call_recorder(
            lambda role_name: f"{role_name}_key"
        )

        tuf.Key.from_securesystemslib_key = key_from_securesystemslib_mock
        test_tuf_management._prepare_root_and_add_it_to_payload = (
            pretend.call_recorder(lambda *a: None)
        )
        test_tuf_management._validate_root_payload_exist = (
            pretend.call_recorder(lambda *a: None)
        )
        result = test_tuf_management.initialize_metadata()

        assert result == test_tuf_management.repository_metadata
        signers_mock.assert_has_calls(
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

    def test_initialize_metadata_signers_less_than_threshold(
        self, test_tuf_management: TUFManagement
    ):
        signers = pretend.call_recorder(lambda *a: ["root_signer"])
        test_tuf_management._signers = signers
        tuf.Role = pretend.call_recorder(lambda *a: "role")

        # Set root threshold higher than the number of keys.
        test_tuf_management.setup.threshold[Roles.ROOT] = 2

        with pytest.raises(ValueError) as err:
            test_tuf_management.initialize_metadata()

        assert "not enough keys" in str(err)
