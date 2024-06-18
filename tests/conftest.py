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
from repository_service_tuf.cli.admin.send.bootstrap import (
    bootstrap as send_bootstrap,
)
from repository_service_tuf.cli.admin.send.sign import sign as send_sign
from repository_service_tuf.cli.admin.send.update import update as send_update
from repository_service_tuf.cli.admin.update import update
from repository_service_tuf.helpers.tuf import (
    BootstrapSetup,
    MetadataInfo,
    Roles,
    RSTUFKey,
    TUFManagement,
)

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
def test_setup() -> BootstrapSetup:
    setup = BootstrapSetup(
        expiration={
            Roles.ROOT: 365,
            Roles.TARGETS: 365,
            Roles.SNAPSHOT: 1,
            Roles.TIMESTAMP: 1,
            Roles.BINS: 1,
        },
        number_of_keys={Roles.ROOT: 2, Roles.TARGETS: 1},
        threshold={
            Roles.ROOT: 1,
            Roles.TARGETS: 1,
        },
        number_of_delegated_bins=256,
        root_keys={},
        online_key=RSTUFKey(),
    )

    return setup


@pytest.fixture
def test_tuf_management(test_setup: BootstrapSetup) -> TUFManagement:
    return TUFManagement(test_setup, False)


@pytest.fixture
def test_inputs() -> Tuple[List[str], List[str], List[str], List[str]]:
    input_step1 = [
        "y",  # Do you want more information about roles and responsibilities?  # noqa
        "y",  # Do you want to start the ceremony?
        "",  # What is the metadata expiration for the root role?(Days)
        "",  # What is the number of keys for the root role? (2)
        "",  # What is the key threshold for root role signing?
        "",  # What is the metadata expiration for the targets role?(Days) (365)?  # noqa
        "y",  # Show example?
        "16",  # Choose the number of delegated hash bin roles
        "",  # What is the metadata expiration for the snapshot role?(Days) (365)?  # noqa
        "",  # What is the metadata expiration for the timestamp role?(Days) (365)?  # noqa
        "",  # What is the metadata expiration for the bins role?(Days) (365)?
    ]
    input_step2 = [
        "",  # Choose ONLINE`s key type [ed25519/ecdsa/rsa] (ed25519)
        "f7a6872f297634219a80141caa2ec9ae8802098b07b67963272603e36cc19fd8",  # Enter ONLINE`s key id  # noqa
        "9fe7ddccb75b977a041424a1fdc142e01be4abab918dc4c611fbfe4a3360a9a8",  # Enter ONLINE`s public key hash   # noqa
        "",  # [Optional] Give a name/tag to the root`s key
    ]
    input_step3 = [
        "y",  # Ready to start loading the root keys? [y/n]
        "",  # Choose root`s key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
        "",  # [Optional] Give a name/tag to the root`s key
        "private",  # Select to use private key or public? [private/public] (public)  # noqa
        "",  # Choose root`s key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/JimiHendrix.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
        "",  # [Optional] Give a name/tag to the root`s key
    ]
    input_step4 = [
        "y",  # Is the online key configuration correct? [y/n]
        "y",  # Is the root configuration correct? [y/n]
        "y",  # Is the targets configuration correct? [y/n]
        "y",  # Is the snapshot configuration correct? [y/n]
        "y",  # Is the timestamp configuration correct? [y/n]
        "y",  # Is the bins configuration correct? [y/n]
    ]

    return input_step1, input_step2, input_step3, input_step4


@pytest.fixture
def ceremony_inputs() -> Tuple[List[str], List[str], List[str], List[str]]:
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
        "0",  # Please press 0 to add key, or remove key by entering its index  # noqa
        f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
        "JimiHendrix's Key",  # Please enter key name
        "0",  # Please press 0 to add key, or remove key by entering its index.  # noqa
        f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
        "JanisJoplin's Key",  # Please enter key name
        "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
        "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
    ]
    input_step3 = [  # Configure Online Key
        f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub'}",  # Please enter path to public key  # noqa
        "Online Key",  # Please enter a key name
    ]
    input_step4 = [  # Sign Metadata
        "1",  # Please enter signing key index
        f"{_PEMS / 'JH.ed25519'}",  # Please enter path to encrypted private key  # noqa
        "1",  # Please enter signing key index
        f"{_PEMS / 'JJ.ecdsa'}",  # Please enter path to encrypted private key  # noqa
    ]

    return input_step1, input_step2, input_step3, input_step4


@pytest.fixture
def root() -> Metadata[Root]:
    return Metadata(Root(expires=datetime.now(timezone.utc)))


@pytest.fixture
def root_info(root: Metadata[Root]) -> MetadataInfo:
    root_keys = [
        SSlibKey("id1", "ed25519", "", {"sha256": "abc"}),
        SSlibKey("id2", "ed25519", "", {"sha256": "foo"}),
    ]
    for key in root_keys:
        root.signed.add_key(key, "root")

    online_key = SSlibKey("id3", "ed25519", "", {"sha256": "doo"})
    for online_role in ["timestamp", "snapshot", "targets"]:
        root.signed.add_key(online_key, online_role)

    return MetadataInfo(root)


@pytest.fixture
def md_update_input() -> Tuple[List[str], List[str], List[str], List[str]]:
    # Step1 will combine current root file name and authorization.
    input_step1 = [
        "tests/files/root.json",  # File name or URL to the current root metadata  # noqa
        "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
    ]
    input_step2 = [
        "y",  # Do you want to extend the root's expiration? [y/n]
        "",  # Days to extend root's expiration starting from today (365)
        "y",  # New root expiration: YYYY-M-DD. Do you agree? [y/n]
    ]
    input_step3 = [
        "y",  # Do you want to modify root keys? [y/n]
        "",  # What should be the root role threshold? (CURRENT_KEY_THRESHOLD)
        "y",  # Do you want to remove a key [y/n]
        "Janis Joplin",  # Name/Tag/ID prefix of the key to remove
        "n",  # Do you want to remove a key [y/n]
        "y",  # Do you want to add a new key? [y/n]
        "",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/JanisJoplin.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
        "Kairo's Key",  # [Optional] Give a name/tag to the key
        "n",  # Do you want to add a new key? [y/n]
        "n",  # Do you want to modify root keys? [y/n]
    ]
    input_step4 = [
        "y",  # Do you want to change the online key? [y/n]
        "rsa",  # Choose root key type [ed25519/ecdsa/rsa] (ed25519)
        "tests/files/key_storage/online-rsa.key",  # Enter the root`s private key path  # noqa
        "strongPass",  # Enter the root`s private key password
        "New RSA Online Key",  # [Optional] Give a name/tag to the key
        "n",  # Do you want to change the online key? [y/n]
    ]
    return input_step1, input_step2, input_step3, input_step4


@pytest.fixture
def metadata_sign_input() -> List[str]:
    input = [
        "http://127.0.0.1",  # API URL address
        "root",  # Choose a metadata to sign [root]
        "y",  # Do you still want to sign root? [y]
        "Jimi Hendrix",  # Choose a private key to load [Jimi Hendrix]
        "",  # Choose Jimi Hendrix key type [ed25519/ecdsa/rsa]
        "tests/files/key_storage/JimiHendrix.key",  # Enter the Jimi Hendrix`s private key path  # noqa
        "strongPass",  # Enter the Jimi Hendrix`s private key password
    ]

    return input


@pytest.fixture
def patch_getpass(monkeypatch):
    """Fixture to mock password prompt return value for encrypted test keys.

    NOTE: we need this, because getpass does not receive the inputs passed to
    click's invoke method (interestingly, click's own password prompt, which
    also uses getpass, does receive them)
    """

    fake_click = pretend.stub(
        prompt=pretend.call_recorder(lambda *a, **kw: "hunter2")
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
    ]
    if cmd in commands_no_out_args:
        out_args = []
    elif cmd == update:
        out_args = ["-s", out_file_name]
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
