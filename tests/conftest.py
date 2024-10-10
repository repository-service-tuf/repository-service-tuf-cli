# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

import pretend
import pytest  # type: ignore
from click import Command, Context
from click.testing import CliRunner, Result  # type: ignore
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from dynaconf import Dynaconf
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import Metadata, Root

from repository_service_tuf.cli.admin.import_artifacts import import_artifacts
from repository_service_tuf.cli.admin.metadata.stop_sign import stop_sign
from repository_service_tuf.cli.admin.send.bootstrap import (
    bootstrap as send_bootstrap,
)
from repository_service_tuf.cli.admin.send.sign import sign as send_sign
from repository_service_tuf.cli.admin.send.update import update as send_update

_FILES = Path(os.path.dirname(__file__)) / "files"
_ROOTS = _FILES / "root"
_PEMS = _FILES / "key_storage"
_PAYLOADS = _FILES / "payload"

# Constants for mocking:
_HELPERS = "repository_service_tuf.cli.admin.helpers"
_PROMPT = "rich.console.Console.input"


def _create_test_context() -> Dict[str, Any]:
    setting_file = os.path.join(TemporaryDirectory().name, "test_settings.yml")
    test_settings = Dynaconf(settings_files=[setting_file])
    return {"settings": test_settings, "config": setting_file}


@pytest.fixture
def test_context() -> Dict[str, Any]:
    return _create_test_context()


def _create_client() -> CliRunner:
    return CliRunner(mix_stderr=False)


@pytest.fixture
def client() -> CliRunner:
    return _create_client()


@pytest.fixture
def ceremony_inputs() -> Tuple[List[str], List[str], List[str], List[str]]:
    # the selection add/remove signing keys is managed by fixture key_selection

    input_step1 = [  # Configure online role settings and root expiration
        "",  # Please enter days until expiry for timestamp role (1)
        "",  # Please enter days until expiry for snapshot role (1)
        "",  # Please enter days until expiry for targets role (365)
        "",  # Please enter days until expiry for bins role (1)
        "4",  # Please enter number of delegated hash bins [2/4/8/16/32/64/128/256/512/1024/2048/4096/8192/16384] (256)  # noqa
        "",  # Please enter days until expiry for root role (365)
    ]
    input_step2 = [  # Configure Root Keys
        "2",  # Please enter root threshold
        f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
        "my rsa key",  # Please enter key name
        f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
        "JimiHendrix's Key",  # Please enter key name
        f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
        "JanisJoplin's Key",  # Please enter key name
    ]
    input_step3 = [  # Configure Online Key
        f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub'}",  # Please enter path to public key  # noqa
        "Online Key",  # Please enter a key name
    ]
    input_step4 = [  # Sign Metadata
        f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        f"{_PEMS / 'JJ.ecdsa'}",  # Please enter path to encrypted private key  # noqa
    ]

    return input_step1, input_step2, input_step3, input_step4


@pytest.fixture
def key_selection() -> lambda *a: str:
    # public key selection options
    selection_options = iter(
        (
            # select delegation type
            "Bins (online key only)",
            # selections for input_step4
            "Key PEM File",  # select key type
            "add",  # add key
            "Key PEM File",  # select key type
            "add",  # add key
            "Key PEM File",  # select key type
            "remove",  # remove key
            "my rsa key",  # select key to remove
            "continue",  # continue
            # selections for input_step4
            "Key PEM File",  # select Online Key type
            "JimiHendrix's Key",  # select key to sign
            "JanisJoplin's Key",  # select key to sign
            "continue",  # continue
        )
    )
    mocked_select = pretend.call_recorder(lambda *a: next(selection_options))

    return mocked_select


@pytest.fixture
def update_inputs():
    return [
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


@pytest.fixture
def update_key_selection() -> lambda *a: str:
    # selections interface
    selection_options = iter(
        (
            # selection for inputs (update root keys)
            "remove",  # remove key
            "JimiHendrix's Key",  # select key to remove
            "add",  # add key
            "Key PEM File",  # select key type
            "continue",  # continue
            "Key PEM File",  # select Online Key type
            # selection for inputs (signing root key)
            "JimiHendrix's Key",  # select key to sign
            "JanisJoplin's Key",  # select key to sign
            "JoeCocker's Key",  # select key to sign
            "continue",  # continue
        )
    )
    mocked_select = pretend.call_recorder(lambda *a: next(selection_options))

    return mocked_select


@pytest.fixture
def root() -> Metadata[Root]:
    return Metadata(Root(expires=datetime.now(timezone.utc)))


@pytest.fixture
def patch_getpass(monkeypatch):
    """Fixture to mock password prompt return value for encrypted test keys.

    NOTE: we need this, because getpass does not receive the inputs passed to
    click's invoke method (interestingly, click's own password prompt, which
    also uses getpass, does receive them)
    """

    fake_click = pretend.stub(
        prompt=pretend.call_recorder(lambda *a, **kw: "hunter2"),
        style=pretend.call_recorder(lambda *a, **kw: ""),
    )
    monkeypatch.setattr(f"{_HELPERS}.click", fake_click)


@pytest.fixture
def patch_utcnow(monkeypatch):
    """Patch `utcnow` in helpers module for reproducible results."""
    fake_replace = pretend.stub(
        replace=pretend.call_recorder(
            lambda **kw: datetime(
                2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc
            )
        )
    )
    fake_datetime = pretend.stub(
        now=pretend.call_recorder(lambda *a: fake_replace)
    )
    monkeypatch.setattr(f"{_HELPERS}.datetime", fake_datetime)


@pytest.fixture
def ed25519_key():
    with open(f"{_PEMS / 'JH.pub'}", "rb") as f:
        public_pem = f.read()

    public_key = load_pem_public_key(public_pem)
    return SSlibKey.from_crypto(public_key, "fake_keyid")


@pytest.fixture
def ed25519_signer(ed25519_key):
    with open(f"{_PEMS / 'JH.ed25519'}", "rb") as f:
        private_pem = f.read()

    private_key = load_pem_private_key(private_pem, b"hunter2")
    return CryptoSigner(private_key, ed25519_key)


def invoke_command(
    cmd: Command,
    inputs: List[str],
    args: List[str],
    test_context: Optional[Context] = None,
    std_err_empty: bool = True,
) -> Result:
    client = _create_client()
    out_file_name = "out_file.json"
    if "--out" in args:
        out_index = args.index("--out")
        out_file_name = args[out_index + 1]

    commands_no_out_args = [
        import_artifacts,
        send_bootstrap,
        send_sign,
        send_update,
        stop_sign,
    ]
    if cmd in commands_no_out_args:
        out_args = []
    else:
        out_args = ["--out", out_file_name]

    if not test_context:
        test_context = _create_test_context()

    with client.isolated_filesystem():
        result_obj = client.invoke(
            cmd,
            args=args + out_args,
            input="\n".join(inputs),
            obj=test_context,
            catch_exceptions=False,
        )

        result_obj.context = test_context
        if std_err_empty:
            assert result_obj.stderr == ""
            if len(out_args) > 0:
                # There are commands that doesn't save a file like
                # 'import_artifacts'. For them out_args is empty.
                with open(out_file_name) as f:
                    result_obj.data = json.load(f)

    return result_obj
