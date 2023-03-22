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
    Delegations,
    Metadata,
    Roles,
    Root,
    RSTUFKey,
    SuccinctRoles,
    Targets,
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
            (["timestamp"], "timestamp", "timestamp"),
        ]
        for files, role_name, expected in positive_test_cases:
            test_tuf_management.repository_metadata = self._setup_load(files)
            result = test_tuf_management._load(role_name)
            if result != expected:
                raise ValueError(f"Expected to load {expected} for {files}")

        # The first list are the existing file names, the second is the role.
        negative_test_cases: Tuple[List[str], str] = [
            (["root"], "timestamp"),
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

    def test__update_timestamp(self, test_tuf_management: TUFManagement):
        # Give a value to snapshot_meta to distinguish the pretend calls as the
        # default for snapshot_meta is
        tuf.MetaFile = pretend.call_recorder(lambda **kwargs: "")
        fake_role = pretend.stub(
            signed=pretend.stub(snapshot_meta=None),
        )
        test_tuf_management._load = pretend.call_recorder(lambda *a: fake_role)
        test_tuf_management._bump_version = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._bump_expiry = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._sign = pretend.call_recorder(lambda *a: None)
        test_tuf_management._add_payload = pretend.call_recorder(
            lambda *a: None
        )
        result = test_tuf_management._update_timestamp(2)
        assert result is None
        assert fake_role.signed.snapshot_meta == ""
        assert tuf.MetaFile.calls == [pretend.call(version=2)]
        assert test_tuf_management._load.calls == [pretend.call("timestamp")]
        assert test_tuf_management._bump_version.calls == [
            pretend.call(fake_role)
        ]
        assert test_tuf_management._bump_expiry.calls == [
            pretend.call(fake_role, "timestamp")
        ]
        assert test_tuf_management._sign.calls == [
            pretend.call(fake_role, "timestamp")
        ]
        assert test_tuf_management._add_payload.calls == [
            pretend.call(fake_role, "timestamp")
        ]

    def test__update_snapshot(self, test_tuf_management: TUFManagement):
        targets_meta: List[Tuple[str, int]] = [("targets", 2), ("bins", 3)]
        fake_role = pretend.stub(
            signed=pretend.stub(
                meta={"targets.json": None, "bins.json": None}, version=2
            ),
        )
        test_tuf_management._load = pretend.call_recorder(lambda *a: fake_role)
        tuf.MetaFile = pretend.call_recorder(lambda **kwargs: "")
        test_tuf_management._bump_expiry = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._bump_version = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._sign = pretend.call_recorder(lambda *a: None)
        test_tuf_management._add_payload = pretend.call_recorder(
            lambda *a: None
        )

        result = test_tuf_management._update_snapshot(targets_meta)
        assert result == 2
        assert fake_role.signed.meta["targets.json"] == ""
        assert fake_role.signed.meta["bins.json"] == ""
        assert test_tuf_management._load.calls == [pretend.call("snapshot")]
        assert tuf.MetaFile.calls == [
            pretend.call(version=2),
            pretend.call(version=3),
        ]
        assert test_tuf_management._bump_expiry.calls == [
            pretend.call(fake_role, "snapshot")
        ]
        assert test_tuf_management._bump_version.calls == [
            pretend.call(fake_role)
        ]
        assert test_tuf_management._sign.calls == [
            pretend.call(fake_role, "snapshot")
        ]
        assert test_tuf_management._add_payload.calls == [
            pretend.call(fake_role, "snapshot")
        ]

    def test__validate_all_roles_payload_exist(
        self, test_tuf_management: TUFManagement
    ):
        metadata = Metadata(Root())
        targets_md = Metadata(
            Targets(
                delegations=Delegations(
                    keys={}, succinct_roles=SuccinctRoles([], 1, 1, "bin")
                )
            )
        )
        load_mock = unittest.mock.Mock()
        # load will be called in this order:
        # root -> targets -> bin-0 -> bin-1 -> snapshot -> timestamp
        load_mock.side_effect = [
            metadata,
            targets_md,
            metadata,
            metadata,
            metadata,
            metadata,
        ]
        test_tuf_management._load = load_mock
        test_tuf_management._validate_all_roles_payload_exist()

        load_mock.assert_has_calls(
            [
                unittest.mock.call("root"),
                unittest.mock.call("targets"),
                unittest.mock.call("bin-0"),
                unittest.mock.call("bin-1"),
                unittest.mock.call("snapshot"),
                unittest.mock.call("timestamp"),
            ]
        )

    def test__validate_all_roles_payload_exist_load_raises(
        self, test_tuf_management: TUFManagement
    ):
        test_tuf_management._load = pretend.raiser(ValueError())

        with pytest.raises(ValueError) as err:
            test_tuf_management._validate_all_roles_payload_exist()

        assert "root is not initialized" in str(err)

    def test__validate_all_roles_payload_exist_role_not_metadata_type(
        self, test_tuf_management: TUFManagement
    ):
        test_tuf_management._load = pretend.call_recorder(lambda *a: "")

        with pytest.raises(ValueError) as err:
            test_tuf_management._validate_all_roles_payload_exist()

        assert "root is not initialized" in str(err)
        assert test_tuf_management._load.calls == [pretend.call("root")]

    def test__setup_targets_and_delegated_md(
        self, test_tuf_management: TUFManagement
    ):
        bins = ["bin-0", "bin-1"]
        fake_succinct_roles = pretend.stub(
            get_roles=pretend.call_recorder(lambda *a: bins),
            keyids=["targets_keyid"],
        )
        test_tuf_management.setup.services.number_of_delegated_bins = 2
        tuf.SuccinctRoles = pretend.call_recorder(
            lambda *a: fake_succinct_roles
        )
        fake_delegation = pretend.stub(succinct_roles=fake_succinct_roles)
        tuf.Delegations = pretend.call_recorder(
            lambda **kwargs: fake_delegation
        )
        fake_targets_md = pretend.stub(
            signed=pretend.stub(
                delegations=None,
                version=1,
                add_key=pretend.call_recorder(lambda *a: None),
            ),
            signatures={"targets_keyid": "targets_sig"},
        )
        test_tuf_management._load = pretend.call_recorder(
            lambda *a: fake_targets_md
        )
        signer = [pretend.stub(key_dict="key_dict")]

        test_tuf_management._signers = pretend.call_recorder(lambda *a: signer)
        tuf.Key = pretend.stub(
            from_securesystemslib_key=pretend.call_recorder(lambda *a: "key")
        )

        bins_hash_role = pretend.stub(signed=pretend.stub(version=2))
        fake_targets = pretend.stub()
        tuf.Targets = pretend.call_recorder(lambda: fake_targets)
        tuf.Targets.type = "targets"
        tuf.Metadata = pretend.call_recorder(lambda *a: bins_hash_role)
        test_tuf_management._bump_expiry = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._bump_version = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._sign = pretend.call_recorder(lambda *a: None)
        test_tuf_management._add_payload = pretend.call_recorder(
            lambda *a: None
        )

        result = test_tuf_management._setup_targets_and_delegated_md()
        assert result == [("bin-0", 2), ("bin-1", 2), ("targets", 1)]
        assert test_tuf_management._load.calls == [pretend.call("targets")]
        assert tuf.SuccinctRoles.calls == [pretend.call([], 1, 1, "bins")]
        assert fake_targets_md.signed.delegations == fake_delegation
        assert tuf.Delegations.calls == [
            pretend.call(keys={}, succinct_roles=fake_succinct_roles)
        ]
        assert fake_succinct_roles.get_roles.calls == [pretend.call()]
        assert test_tuf_management._signers.calls == [
            pretend.call(Roles.BINS),
            pretend.call(Roles.BINS),
        ]
        assert fake_targets_md.signed.add_key.calls == [
            pretend.call("key", "bin-0"),
            pretend.call("key", "bin-1"),
        ]
        assert tuf.Key.from_securesystemslib_key.calls == [
            pretend.call("key_dict"),
            pretend.call("key_dict"),
        ]
        assert tuf.Metadata.calls == [
            pretend.call(fake_targets),
            pretend.call(fake_targets),
        ]
        assert test_tuf_management._bump_expiry.calls == [
            pretend.call(bins_hash_role, "bins"),
            pretend.call(bins_hash_role, "bins"),
            pretend.call(fake_targets_md, "targets"),
        ]
        assert test_tuf_management._sign.calls == [
            pretend.call(bins_hash_role, "bins"),
            pretend.call(bins_hash_role, "bins"),
            pretend.call(fake_targets_md, "targets"),
        ]
        assert test_tuf_management._add_payload.calls == [
            pretend.call(bins_hash_role, "bin-0"),
            pretend.call(bins_hash_role, "bin-1"),
            pretend.call(fake_targets_md, "targets"),
        ]
        assert test_tuf_management._bump_version.calls == [
            pretend.call(fake_targets_md)
        ]

    def test__setup_targets_and_delegated_md_bins_lots_of_keys(
        self, test_tuf_management: TUFManagement
    ):
        bins = ["bin-0", "bin-1"]
        fake_succinct_roles = pretend.stub(
            get_roles=pretend.call_recorder(lambda *a: bins),
        )
        test_tuf_management.setup.services.number_of_delegated_bins = 2
        tuf.SuccinctRoles = pretend.call_recorder(
            lambda *a: fake_succinct_roles
        )
        fake_delegation = pretend.stub(succinct_roles=fake_succinct_roles)
        tuf.Delegations = pretend.call_recorder(
            lambda **kwargs: fake_delegation
        )
        fake_targets_md = pretend.stub(
            signed=pretend.stub(
                delegations=None,
            ),
            signatures={"keyid": "targets_sig"},
        )
        test_tuf_management._load = pretend.call_recorder(
            lambda *a: fake_targets_md
        )
        signers = [
            pretend.stub(key_dict="key_dict1"),
            pretend.stub(key_dict="key_dict2"),
        ]

        test_tuf_management._signers = pretend.call_recorder(
            lambda *a: signers
        )

        with pytest.raises(ValueError) as err:
            test_tuf_management._setup_targets_and_delegated_md()

        assert "BINS role must use exactly one online key" in str(err)
        assert test_tuf_management._load.calls == [pretend.call("targets")]
        assert tuf.SuccinctRoles.calls == [pretend.call([], 1, 1, "bins")]
        assert fake_targets_md.signed.delegations == fake_delegation
        assert tuf.Delegations.calls == [
            pretend.call(keys={}, succinct_roles=fake_succinct_roles)
        ]
        assert fake_succinct_roles.get_roles.calls == [pretend.call()]
        assert test_tuf_management._signers.calls == [
            pretend.call(Roles.BINS),
        ]

    def test__setup_targets_and_delegated_md_wrong_key_for_bins(
        self, test_tuf_management: TUFManagement
    ):
        bins = ["bin-0", "bin-1"]
        fake_succinct_roles = pretend.stub(
            get_roles=pretend.call_recorder(lambda *a: bins),
            keyids=["other_keyid"],
        )
        test_tuf_management.setup.services.number_of_delegated_bins = 2
        tuf.SuccinctRoles = pretend.call_recorder(
            lambda *a: fake_succinct_roles
        )
        fake_delegation = pretend.stub(succinct_roles=fake_succinct_roles)
        tuf.Delegations = pretend.call_recorder(
            lambda **kwargs: fake_delegation
        )
        fake_targets_md = pretend.stub(
            signed=pretend.stub(
                delegations=None,
                add_key=pretend.call_recorder(lambda *a: None),
            ),
            signatures={"keyid": "targets_sig"},
        )
        test_tuf_management._load = pretend.call_recorder(
            lambda *a: fake_targets_md
        )
        signer = [pretend.stub(key_dict="key_dict")]

        test_tuf_management._signers = pretend.call_recorder(lambda *a: signer)
        tuf.Key = pretend.stub(
            from_securesystemslib_key=pretend.call_recorder(lambda *a: "key")
        )

        with pytest.raises(ValueError) as err:
            test_tuf_management._setup_targets_and_delegated_md()

        assert "BINS key id must be the same as the targets key id" in str(err)
        assert test_tuf_management._load.calls == [pretend.call("targets")]
        assert tuf.SuccinctRoles.calls == [pretend.call([], 1, 1, "bins")]
        assert fake_targets_md.signed.delegations == fake_delegation
        assert tuf.Delegations.calls == [
            pretend.call(keys={}, succinct_roles=fake_succinct_roles)
        ]
        assert fake_succinct_roles.get_roles.calls == [pretend.call()]
        assert test_tuf_management._signers.calls == [
            pretend.call(Roles.BINS),
        ]
        assert fake_targets_md.signed.add_key.calls == [
            pretend.call("key", "bin-0"),
        ]
        assert tuf.Key.from_securesystemslib_key.calls == [
            pretend.call("key_dict"),
        ]

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
        fake_targets = pretend.stub(signed=pretend.stub(type="targets"))
        fake_snapshot = pretend.stub(signed=pretend.stub(type="snapshot"))
        fake_timestamp = pretend.stub(signed=pretend.stub(type="timestamp"))
        fake_root = pretend.stub(
            signed=pretend.stub(
                type="root", add_key=pretend.call_recorder(lambda *a: None)
            ),
        )
        tuf.Targets = pretend.call_recorder(lambda: fake_targets)
        tuf.Snapshot = pretend.call_recorder(lambda: fake_snapshot)
        tuf.Timestamp = pretend.call_recorder(lambda: fake_timestamp)
        tuf.Root = pretend.call_recorder(lambda **kwargs: fake_root)

        mock_md_creation = unittest.mock.Mock()
        mock_md_creation.side_effect = [
            fake_targets,
            fake_snapshot,
            fake_timestamp,
            fake_root,
        ]
        tuf.Metadata = mock_md_creation

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

        test_tuf_management._prepare_top_level_md_and_add_to_payload(
            {}, add_key_args
        )
        assert tuf.Targets.calls == [pretend.call()]
        assert tuf.Snapshot.calls == [pretend.call()]
        assert tuf.Timestamp.calls == [pretend.call()]
        assert tuf.Root.calls == [pretend.call(roles={})]
        assert tuf.Metadata.call_args_list == [
            unittest.mock.call(fake_targets),
            unittest.mock.call(fake_snapshot),
            unittest.mock.call(fake_timestamp),
            unittest.mock.call(fake_root),
        ]
        assert test_tuf_management._verify_correct_keys_usage.calls == [
            pretend.call(fake_root.signed)
        ]
        assert test_tuf_management._bump_expiry.calls == [
            pretend.call(fake_targets, "targets"),
            pretend.call(fake_snapshot, "snapshot"),
            pretend.call(fake_timestamp, "timestamp"),
            pretend.call(fake_root, "root"),
        ]
        assert test_tuf_management._sign.calls == [
            pretend.call(fake_targets, "targets"),
            pretend.call(fake_snapshot, "snapshot"),
            pretend.call(fake_timestamp, "timestamp"),
            pretend.call(fake_root, "root"),
        ]
        assert test_tuf_management._add_payload.calls == [
            pretend.call(fake_targets, "targets"),
            pretend.call(fake_snapshot, "snapshot"),
            pretend.call(fake_timestamp, "timestamp"),
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
        test_tuf_management._prepare_top_level_md_and_add_to_payload = (
            pretend.call_recorder(lambda *a: None)
        )
        test_tuf_management._setup_targets_and_delegated_md = (
            pretend.call_recorder(lambda *a: [])
        )
        test_tuf_management._update_snapshot = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._update_timestamp = pretend.call_recorder(
            lambda *a: None
        )
        test_tuf_management._validate_all_roles_payload_exist = (
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
            test_tuf_management._prepare_top_level_md_and_add_to_payload.calls
            == [pretend.call(expected_roles, expected_add_key_args)]
        )
        assert test_tuf_management._setup_targets_and_delegated_md.calls == [
            pretend.call()
        ]
        assert test_tuf_management._update_snapshot.calls == [pretend.call([])]
        assert test_tuf_management._update_timestamp.calls == [
            pretend.call(None)
        ]
        assert test_tuf_management._validate_all_roles_payload_exist.calls == [
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
