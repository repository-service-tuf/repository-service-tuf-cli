# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT

# from unittest.mock import Mock

import unittest.mock
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

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

    def test__load(self, test_tuf_management: TUFManagement):
        # The first list are the existing file names, the second is the role
        # that we want to load and the third string is the expected result.
        positive_test_cases: List[Tuple[List[str], str, str]] = [
            (["1.root", "10.root", "3.root"], "root", "10.root"),
        ]
        for files, role_name, expected in positive_test_cases:
            test_tuf_management.repository_metadata = self._setup_load(files)
            result = test_tuf_management._load(role_name)
            if result != expected:
                raise ValueError(f"Expected to load {expected} for {files}")

        # The first list are the existing file names, the second is the role.
        negative_test_cases: Tuple[List[str], str] = [
            (["root"], "root"),
            (["0.root"], "root"),
            (["-1.root"], "root"),
            (["1.root"], "non-existent"),
            (["1.non-existent"], "root"),
        ]
        files = []
        role_name = ""
        for files, role_name in negative_test_cases:
            test_tuf_management.repository_metadata = self._setup_load(files)
            with pytest.raises(ValueError):
                result = test_tuf_management._load(role_name)

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
        fake_role = pretend.stub(signed=pretend.stub(version=2))
        test_tuf_management._add_payload(fake_role, "root")
        assert test_tuf_management.repository_metadata["2.root"] == fake_role

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
        assert test_tuf_management.repository_metadata["2.root"] == fake_role
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

    def test__bump_version(self, test_tuf_management: TUFManagement):
        fake_role = pretend.stub(
            signed=pretend.stub(version=2),
        )
        test_tuf_management._bump_version(fake_role)
        assert fake_role.signed.version == 3

    def test__validate_root_payload_exist(
        self, test_tuf_management: TUFManagement
    ):
        root_md = Metadata(Root())
        test_tuf_management._load = pretend.call_recorder(lambda *a: root_md)
        result = test_tuf_management._validate_root_payload_exist()

        assert result is None
        assert test_tuf_management._load.calls == [pretend.call("root")]

    def test__validate_root_payload_exist_exist_load_raises(
        self, test_tuf_management: TUFManagement
    ):
        test_tuf_management._load = pretend.raiser(ValueError())

        with pytest.raises(ValueError) as err:
            test_tuf_management._validate_root_payload_exist()

        assert "Root is not initialized" in str(err)

    def test__validate_root_payload_exist_role_not_metadata_type(
        self, test_tuf_management: TUFManagement
    ):
        test_tuf_management._load = pretend.call_recorder(lambda *a: "")

        with pytest.raises(ValueError) as err:
            test_tuf_management._validate_root_payload_exist()

        assert "Root is not initialized" in str(err)
        assert test_tuf_management._load.calls == [pretend.call("root")]

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
        add_key_args = [("key1", "role1"), ("key2", "role2")]

        test_tuf_management._prepare_root_and_add_it_to_payload(
            {}, add_key_args
        )
        assert tuf.Root.calls == [pretend.call(roles={})]
        assert tuf.Metadata.calls == [pretend.call(fake_root.signed)]
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
        expected_add_key_args: List[Tuple[str, str]] = [
            ("root_key", "root"),
            ("timestamp_key", "timestamp"),
            ("snapshot_key", "snapshot"),
            ("targets_key", "targets"),
        ]
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
