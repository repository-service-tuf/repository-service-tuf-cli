# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json

import click
import pretend
import pytest
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin import update
from tests.conftest import _HELPERS, _PAYLOADS, _PEMS, _ROOTS, invoke_command

MOCK_PATH = "repository_service_tuf.cli.admin.update"


class TestMetadataUpdate:
    def test_update_input(self, monkeypatch, patch_getpass, patch_utcnow):
        inputs = [
            "n",  # Do you want to change the expiry date? [y/n] (y)
            "n",  # Do you want to change the threshold? [y/n] (n)
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "JoeCocker's Key",  # Please enter a key name
            "y",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'cb20fa1061dde8e6267e0bef0981766aaadae168e917030f7f26edc7a0bab9c2.pub'}",  # Please enter path to public key  # noqa
            "New Online Key",  # Please enter a key name
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JJ.ecdsa'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JC.rsa'}",  # Please enter path to encrypted private key  # noqa
        ]
        args = ["--in", f"{_ROOTS / 'v1.json'}"]

        # selections interface
        selection_options = iter(
            (
                # selection for inputs (update root keys)
                "remove",  # add key
                "JimiHendrix's Key",  # add key
                "add",  # remove key
                "continue",  # continue
                # selection for inputs (signing root key)
                "JimiHendrix's Key",  # select key to sign
                "JanisJoplin's Key",  # select key to sign
                "JoeCocker's Key",  # select key to sign
                "continue",  # continue
            )
        )
        mocked_select = pretend.call_recorder(
            lambda *a: next(selection_options)
        )

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", mocked_select)
        result = invoke_command(update.update, inputs, args)
        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

    def test_update_metadata_url(
        self, monkeypatch, patch_getpass, patch_utcnow
    ):
        inputs = [
            "n",  # Do you want to change the expiry date? [y/n] (y)
            "n",  # Do you want to change the threshold? [y/n] (n)
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "JoeCocker's Key",  # Please enter a key name
            "y",  # Do you want to change the online key? [y/n] (y)
            f"{_PEMS / 'cb20fa1061dde8e6267e0bef0981766aaadae168e917030f7f26edc7a0bab9c2.pub'}",  # Please enter path to public key  # noqa
            "New Online Key",  # Please enter a key name
            f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JJ.ecdsa'}",  # Please enter path to encrypted private key  # noqa
            f"{_PEMS / 'JC.rsa'}",  # Please enter path to encrypted private key  # noqa
        ]
        root_md = Metadata.from_file(f"{_ROOTS / 'v1.json'}")
        fake_get_latest_md = pretend.call_recorder(lambda *a: root_md)
        monkeypatch.setattr(f"{MOCK_PATH}.get_latest_md", fake_get_latest_md)
        fake_url = "http://fake-server/1.root.json"
        args = ["--metadata-url", fake_url]

        # selections interface
        selection_options = iter(
            (
                # selection for inputs (update root keys)
                "remove",  # add key
                "JimiHendrix's Key",  # add key
                "add",  # remove key
                "continue",  # continue
                # selection for inputs (signing root key)
                "JimiHendrix's Key",  # select key to sign
                "JanisJoplin's Key",  # select key to sign
                "JoeCocker's Key",  # select key to sign
                "continue",  # continue
            )
        )
        mocked_select = pretend.call_recorder(
            lambda *a: next(selection_options)
        )

        # public key selection options
        monkeypatch.setattr(f"{_HELPERS}._select", mocked_select)
        result = invoke_command(update.update, inputs, args)
        with open(_PAYLOADS / "update.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert fake_get_latest_md.calls == [pretend.call(fake_url, Root.type)]


class TestUpdateError:
    def test_update_no_input_or_root_url(self):
        result = invoke_command(update.update, [], [], std_err_empty=False)
        assert "Either '--in' or '--metadata-url' needed" in result.stderr


class TestMetadaUpdateHelpers:
    def test_get_latest_md_root_not_exists(self, monkeypatch):
        fake_dir_name = "foo_bar_dir"

        class FakeTempDir:
            def __init__(self) -> None:
                self.name = fake_dir_name

        monkeypatch.setattr(f"{MOCK_PATH}.TemporaryDirectory", FakeTempDir)
        fake_response = pretend.stub(status_code=200, text="foo bar")
        fake_requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        monkeypatch.setattr(f"{MOCK_PATH}.requests", fake_requests)

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
            update.__builtins__, "open", lambda *a: FakeFileDescriptor(*a)
        )

        class FakeUpdater:
            def __init__(self, **kw) -> None:
                self.new_args = kw
                self.refresh_calls_amount = 0

            def refresh(self) -> None:
                self.refresh_calls_amount += 1

        monkeypatch.setattr(f"{MOCK_PATH}.Updater", FakeUpdater)
        fake_root_result = pretend.stub()
        fake_metadata = pretend.stub(
            from_file=pretend.call_recorder(lambda a: fake_root_result)
        )
        monkeypatch.setattr(f"{MOCK_PATH}.Metadata", fake_metadata)
        fake_url = "http://localhost:8080"

        result = update.get_latest_md(fake_url, Root.type)

        assert result == fake_root_result
        assert fake_requests.get.calls == [
            pretend.call(f"{fake_url}/1.root.json", timeout=300)
        ]
        assert fake_destination_file.write.calls == [
            pretend.call(fake_response.text)
        ]
        assert fake_metadata.from_file.calls == [
            pretend.call(f"{fake_dir_name}/{Root.type}.json")
        ]

    def test_get_latest_md_root_not_exist_response_not_200(self, monkeypatch):
        fake_dir_name = "foo_bar_dir"

        class FakeTempDir:
            def __init__(self) -> None:
                self.name = fake_dir_name

        monkeypatch.setattr(f"{MOCK_PATH}.TemporaryDirectory", FakeTempDir)
        fake_response = pretend.stub(status_code=400)
        fake_requests = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: fake_response)
        )
        monkeypatch.setattr(f"{MOCK_PATH}.requests", fake_requests)

        fake_url = "http://localhost:8080"

        with pytest.raises(click.ClickException) as e:
            update.get_latest_md(fake_url, Root.type)

        assert "Cannot fetch initial root " in str(e)

    def test_get_latest_md_root_OS_error(self, monkeypatch):
        fake_dir_name = "foo_bar_dir"

        class FakeTempDir:
            def __init__(self) -> None:
                self.name = fake_dir_name

        monkeypatch.setattr(f"{MOCK_PATH}.TemporaryDirectory", FakeTempDir)
        fake_url = "http://localhost:8080"

        with pytest.raises(click.ClickException) as e:
            update.get_latest_md(fake_url, Root.type)

        assert "Problem fetching latest" in str(e)
