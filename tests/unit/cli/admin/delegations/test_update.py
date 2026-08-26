# SPDX-FileCopyrightText: 2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

from unittest.mock import patch

import pretend
import pytest
from tuf.api.metadata import (
    Delegations,
    SuccinctRoles,
    Targets,
)

from repository_service_tuf.cli.admin.delegations import update
from repository_service_tuf.cli.admin.helpers import (
    KEY_NAME_FIELD,
    KEY_URI_FIELD,
    NESTED_BINS_FIELD,
    ROLE_ONLINE_KEY_FIELD,
    _configure_delegation_update,
    _delegation_key_label,
    _delegation_update_problems,
)
from repository_service_tuf.helpers.api_client import URL, Methods
from tests.conftest import _HELPERS, invoke_command
from tests.unit.cli.admin.delegations.conftest import (
    OFFLINE_KEY_A,
    delegated_role,
    key_path,
    load_public_key,
)

MOCK_PATH = "repository_service_tuf.cli.admin.delegations.update"
METADATA_URL = "http://metadata.example"


def _patch_metadata(monkeypatch, targets_md):
    """Serve targets the way `--metadata-url` would."""
    fake = pretend.call_recorder(lambda url, role: targets_md)
    monkeypatch.setattr(f"{MOCK_PATH}._get_latest_md", fake)

    return fake


def _patch_selections(monkeypatch, selections):
    options = iter(selections)
    mocked = pretend.call_recorder(lambda *a: next(options))
    monkeypatch.setattr(f"{_HELPERS}._select", mocked)

    return mocked


def _patch_public_key(monkeypatch, filename):
    prompt = pretend.call_recorder(lambda *a: key_path(filename))
    monkeypatch.setattr(f"{_HELPERS}._prompt_public_key", prompt)

    return prompt


def _role(result) -> dict:
    """The single delegated role carried by an update payload."""
    roles = result.data["delegations"]["roles"]
    assert len(roles) == 1

    return roles[0]


def _flat(text: str) -> str:
    """Collapse rich's line wrapping and panel borders to match messages."""
    return " ".join(text.replace("│", " ").split())


class TestDelegationsUpdate:
    def test_edit_paths_threshold_and_expiry(self, monkeypatch, targets_md):
        _patch_metadata(monkeypatch, targets_md)
        _patch_selections(
            monkeypatch,
            [
                "pytorch",  # role to update
                "edit paths",
                "add new path",
                "continue",  # paths
                "edit threshold",
                "edit expiration",
                "continue",  # role
            ],
        )

        result = invoke_command(
            update.update,
            [
                "pytorch/nightly/*",  # Please enter path
                "1",  # Please enter 'pytorch' threshold
                "90",  # Please enter days until expiry
            ],
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        role = _role(result)
        assert role["paths"] == ["pytorch/*", "pytorch/nightly/*"]
        assert role["threshold"] == 1
        assert role["x-rstuf-expire-policy"] == 90

    def test_switch_to_the_repository_online_key(
        self, monkeypatch, targets_md
    ):
        """An offline-signed role can be handed back to the online key."""
        _patch_metadata(monkeypatch, targets_md)
        _patch_selections(
            monkeypatch,
            [
                "pytorch",
                "manage signing keys",
                "use the repository online key",
                "continue",  # keys
                "continue",  # role
            ],
        )

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        role = _role(result)
        # Empty keyids mean the repository online key, which the Worker fills
        # in; the threshold has to come back down with it.
        assert role["keyids"] == []
        assert role["threshold"] == 1
        assert result.data["delegations"]["keys"] == {}

    def test_add_offline_key(self, monkeypatch, targets_md, repository_key):
        """`advisories` moves off the online key onto an offline one."""
        _patch_metadata(monkeypatch, targets_md)
        _patch_public_key(monkeypatch, OFFLINE_KEY_A)
        added = load_public_key(OFFLINE_KEY_A, "unused")
        _patch_selections(
            monkeypatch,
            [
                "advisories",
                "manage signing keys",
                "add an offline key",
                "Key PEM File",  # key type
                "continue",  # keys
                "continue",  # role
            ],
        )

        result = invoke_command(
            update.update,
            ["security-team"],  # Please enter key name
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        role = _role(result)
        assert role["keyids"] == [repository_key.keyid, added.keyid]

        keys = result.data["delegations"]["keys"]
        assert keys[added.keyid][KEY_NAME_FIELD] == "security-team"
        assert KEY_URI_FIELD not in keys[added.keyid]

    def test_remove_a_key(self, monkeypatch, targets_md, offline_keys):
        _patch_metadata(monkeypatch, targets_md)
        offline_a, offline_b = list(offline_keys)
        label = _delegation_key_label(
            offline_a, targets_md.signed.delegations
        )
        selections = _patch_selections(
            monkeypatch,
            [
                "pytorch",
                "manage signing keys",
                "remove a key",
                label,
                "continue",  # keys
                "edit threshold",  # dropping a key left it too high
                "continue",  # role
            ],
        )

        result = invoke_command(
            update.update,
            ["1"],  # Please enter 'pytorch' threshold
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        role = _role(result)
        assert role["keyids"] == [offline_b]
        assert role["threshold"] == 1
        assert list(result.data["delegations"]["keys"]) == [offline_b]
        # The outer editor withholds 'continue' while the threshold exceeds
        # the keys the role still trusts.
        assert "continue" not in selections.calls[5].args[0]

    def test_nested_bins_role_keeps_its_online_key(
        self, monkeypatch, targets_md, role_online_key, repository_key
    ):
        """The bins' key is not a role keyid, but the payload must carry it.

        The API rejects an `x-rstuf-role-online-key` it cannot resolve in
        `delegations.keys`, so an update of an unrelated field still has to
        re-send the key.
        """
        _patch_metadata(monkeypatch, targets_md)
        _patch_selections(
            monkeypatch, ["fastapi", "edit expiration", "continue"]
        )

        result = invoke_command(
            update.update,
            ["45"],  # Please enter days until expiry
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        role = _role(result)
        assert role[NESTED_BINS_FIELD] == 16
        assert role[ROLE_ONLINE_KEY_FIELD] == role_online_key.keyid
        # The bins' key signs the bins, never the role itself.
        assert role_online_key.keyid not in role["keyids"]

        keys = result.data["delegations"]["keys"]
        assert role_online_key.keyid in keys
        assert repository_key.keyid in keys

    def test_nested_bins_role_cannot_take_offline_keys(
        self, monkeypatch, targets_md
    ):
        """The Worker signs the bins, so it must be able to sign the role."""
        _patch_metadata(monkeypatch, targets_md)
        selections = _patch_selections(
            monkeypatch,
            ["fastapi", "manage signing keys", "continue", "continue"],
        )

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        # The key menu is the third _select call; it must not offer offline
        # keys for a role that has nested hash bins.
        key_menu_options = selections.calls[2].args[0]
        assert "add an offline key" not in key_menu_options

    def test_threshold_problem_blocks_leaving_the_editor(
        self, monkeypatch, targets_md
    ):
        _patch_metadata(monkeypatch, targets_md)
        selections = _patch_selections(
            monkeypatch,
            [
                "pytorch",
                "edit threshold",  # raise it beyond the trusted keys
                "edit threshold",  # put it back
                "continue",
            ],
        )

        result = invoke_command(
            update.update,
            ["5", "2"],  # thresholds
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        # 'continue' is withheld while the threshold exceeds the trusted keys.
        assert "continue" not in selections.calls[2].args[0]
        assert "continue" in selections.calls[3].args[0]
        assert _role(result)["threshold"] == 2

    def test_role_without_paths_must_gain_one(self, monkeypatch, targets_md):
        targets_md.signed.delegations.roles["pytorch"].paths = []
        _patch_metadata(monkeypatch, targets_md)
        selections = _patch_selections(
            monkeypatch,
            ["pytorch", "edit paths", "continue", "continue"],
        )

        result = invoke_command(
            update.update,
            ["pytorch/*"],  # Please enter path
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        assert "continue" not in selections.calls[1].args[0]
        assert _role(result)["paths"] == ["pytorch/*"]

    def test_path_hash_prefix_role_refused(self, monkeypatch, targets_md):
        role = targets_md.signed.delegations.roles["pytorch"]
        role.paths = None
        role.path_hash_prefixes = ["ab"]
        _patch_metadata(monkeypatch, targets_md)
        _patch_selections(monkeypatch, ["pytorch"])

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
            std_err_empty=False,
        )

        assert result.exit_code == 1
        assert "delegates by path hash prefix" in _flat(result.stderr)

    def test_sends_put_to_the_delegations_endpoint(
        self, monkeypatch, targets_md, test_context
    ):
        _patch_metadata(monkeypatch, targets_md)
        _patch_selections(
            monkeypatch, ["fastapi", "edit expiration", "continue"]
        )
        fake_send_payload = pretend.call_recorder(
            lambda *a, **kw: "task_id_123"
        )
        monkeypatch.setattr(f"{MOCK_PATH}.send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(f"{MOCK_PATH}.task_status", fake_task_status)
        test_context["settings"].SERVER = "http://fake-rstuf"

        result = invoke_command(
            update.update,
            ["45"],  # Please enter days until expiry
            ["--metadata-url", METADATA_URL],
            test_context,
        )

        assert result.exit_code == 0, result.stderr
        assert len(fake_send_payload.calls) == 1
        call = fake_send_payload.calls[0]
        assert call.args[1] == URL.DELEGATIONS.value
        assert call.args[3] == "Metadata delegation update accepted."
        # An update is a PUT: the POST endpoint creates a delegation.
        assert call.kwargs == {"method": Methods.PUT}
        assert _role(result)["x-rstuf-expire-policy"] == 45
        assert len(fake_task_status.calls) == 1

    def test_no_server_and_no_dry_run(self, monkeypatch, targets_md):
        _patch_metadata(monkeypatch, targets_md)

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL],
            std_err_empty=False,
        )

        assert result.exit_code == 1
        assert "'--dry-run' needed" in _flat(result.stderr)

    def test_targets_without_delegations(self, monkeypatch, targets_md):
        targets_md.signed.delegations = None
        _patch_metadata(monkeypatch, targets_md)

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
            std_err_empty=False,
        )

        assert result.exit_code == 1
        assert "Metadata has no delegations." in _flat(result.stderr)

    def test_succinct_roles_refused(
        self, monkeypatch, targets_md, repository_key
    ):
        targets_md.signed.delegations = Delegations(
            keys={repository_key.keyid: repository_key},
            succinct_roles=SuccinctRoles(
                keyids=[repository_key.keyid],
                threshold=1,
                bit_length=8,
                name_prefix="bins",
            ),
        )
        _patch_metadata(monkeypatch, targets_md)

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
            std_err_empty=False,
        )

        assert result.exit_code == 1
        assert "Metadata uses succinct roles" in _flat(result.stderr)

    def test_no_delegated_roles_to_update(self):
        with pytest.raises(Exception) as err:
            _configure_delegation_update(Delegations(keys={}, roles={}))

        assert "Metadata has no delegated roles." in str(err.value)


class TestDelegationUpdateProblems:
    """The rules checked locally so the editor does not send a doomed PUT."""

    def test_no_problems(self):
        role = delegated_role("fastapi", ["aaa"])
        delegations = Delegations(keys={}, roles={"fastapi": role})

        assert _delegation_update_problems(role, delegations) == []

    def test_role_without_paths(self):
        role = delegated_role("fastapi", ["aaa"])
        role.paths = []
        delegations = Delegations(keys={}, roles={"fastapi": role})

        assert _delegation_update_problems(role, delegations) == [
            "The role needs at least one path."
        ]

    def test_threshold_above_assigned_keys(self):
        role = delegated_role("fastapi", ["aaa"], threshold=2)
        delegations = Delegations(keys={}, roles={"fastapi": role})

        problems = _delegation_update_problems(role, delegations)
        assert problems == [
            "Threshold 2 exceeds the 1 key(s) the role trusts."
        ]

    def test_online_key_requires_threshold_one(self):
        role = delegated_role("fastapi", [], threshold=2)
        delegations = Delegations(keys={}, roles={"fastapi": role})

        assert _delegation_update_problems(role, delegations) == [
            "The repository online key requires threshold 1."
        ]

    def test_nested_bins_reject_offline_keys(self):
        role = delegated_role("fastapi", ["offline"], num_bins=16)
        delegations = Delegations(keys={}, roles={"fastapi": role})

        problems = _delegation_update_problems(role, delegations)
        assert any("not by offline keys" in problem for problem in problems)

    def test_nested_bins_on_the_online_key_are_fine(self):
        role = delegated_role("fastapi", [], num_bins=16)
        delegations = Delegations(keys={}, roles={"fastapi": role})

        assert _delegation_update_problems(role, delegations) == []


class TestDelegationKeyLabel:
    def test_named_key(self, targets_md, offline_keys):
        offline_a = list(offline_keys)[0]
        label = _delegation_key_label(
            offline_a, targets_md.signed.delegations
        )

        assert label == f"JH ({offline_a})"

    def test_unknown_key(self):
        delegations = Delegations(keys={}, roles={})

        assert _delegation_key_label("abc", delegations) == "abc (unknown key)"


class TestMetadataUpdateHelpers:
    def test_only_targets_is_fetched(self, monkeypatch, targets_md):
        """Root is not needed: there is no key catalogue to reconcile."""
        fetch = _patch_metadata(monkeypatch, targets_md)
        _patch_selections(monkeypatch, ["pytorch", "continue"])

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        assert [call.args[1] for call in fetch.calls] == [Targets.type]

    def test_missing_expire_policy_is_defaulted(
        self, monkeypatch, targets_md
    ):
        """Older metadata may predate the expire policy field."""
        role = targets_md.signed.delegations.roles["pytorch"]
        del role.unrecognized_fields["x-rstuf-expire-policy"]
        _patch_metadata(monkeypatch, targets_md)
        _patch_selections(monkeypatch, ["pytorch", "continue"])

        result = invoke_command(
            update.update,
            [],
            ["--metadata-url", METADATA_URL, "--dry-run"],
        )

        assert result.exit_code == 0, result.stderr
        assert _role(result)["x-rstuf-expire-policy"] == 1


class TestRoleOnlineKeyRecovery:
    """The payload must declare the key its role names, or say why it can't."""

    def test_role_online_key_is_resent(self, targets_md, role_online_key):
        current = targets_md.signed.delegations
        with patch(f"{_HELPERS}._select", side_effect=["fastapi", "continue"]):
            updated = _configure_delegation_update(current)

        role = updated.roles["fastapi"]
        keyid = role.unrecognized_fields[ROLE_ONLINE_KEY_FIELD]
        assert keyid == role_online_key.keyid
        # Declared, so the API can resolve the reference ...
        assert keyid in updated.keys
        # ... but still not something the role itself signs with.
        assert keyid not in role.keyids

    def test_undeclared_role_online_key_is_refused(self, targets_md):
        """Metadata from an older Worker records the id but not the key."""
        current = targets_md.signed.delegations
        keyid = current.roles["fastapi"].unrecognized_fields[
            ROLE_ONLINE_KEY_FIELD
        ]
        del current.keys[keyid]

        with patch(f"{_HELPERS}._select", side_effect=["fastapi", "continue"]):
            with pytest.raises(Exception) as err:
                _configure_delegation_update(current)

        assert "does not declare that key" in str(err.value)
        assert "re-create it" in str(err.value)
