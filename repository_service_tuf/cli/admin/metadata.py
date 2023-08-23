# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from rich import box, markdown, prompt, table
from securesystemslib.exceptions import StorageError  # type: ignore
from securesystemslib.signer import Signature  # type: ignore
from tuf.api.metadata import Metadata, Root
from tuf.api.serialization import DeserializationError

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    get_headers,
    get_md_file,
    request_server,
    send_payload,
    task_status,
)
from repository_service_tuf.helpers.tuf import (
    MetadataInfo,
    RSTUFKey,
    UnsignedMetadataError,
    load_key,
    load_payload,
    save_payload,
)

INTRODUCTION = """
# Metadata Update

The metadata update ceremony allows to:
- extend Root expiration
- change Root signature threshold
- change any signing key
"""

CURRENT_ROOT_INFO = """
# Current Root Content

Before deciding what you want to update it's recommended that you
get familiar with the current state of the root metadata file.
"""

AUTHORIZATION = """
# STEP 1: Authorization

Before continuing, you must authorize using the current root key(s).

In order to complete the authorization you will be asked to provide information
about one or more keys used to sign the current root metadata.
To complete the authorization, you must provide information about one or more
keys used to sign the current root metadata.
The number of required keys is based on the current "threshold".

You will need local access to the keys as well as their corresponding
passwords.
"""

EXPIRY_CHANGES_MSG = """
# STEP 2: Extend Root Expiration

Now, you will be given the opportunity to extend root's expiration.

Note: the root expiration can be extended ONLY during the metadata update
ceremony.
"""

ROOT_KEYS_CHANGES_MSG = """
# STEP 3:  Root Keys Changes

You are starting the Root keys changes procedure.

Note: when asked about specific attributes the default values that are
suggested will be the ones used in the current root metadata.
"""

ROOT_KEYS_REMOVAL_MSG = """
## Root Keys Removal

You are starting the root keys modification procedure.

First, you will be asked if you want to remove any of the keys.
Then you will be given the opportunity to add as many keys as you want.

In the end, the number of keys that are left must be equal or above the
threshold you have given.
"""

ROOT_KEY_ADDITIONS_MSG = """
## Root Keys Addition

Now, you will be able to add root keys.
"""

ONLINE_KEY_CHANGE = """
# STEP 4: Online Key Change

Now you will be given the opportunity to change the online key.

The online key is used to sign all roles except root.

Note: there can be only one online key at a time.
"""

METADATA_SIGNING = """
# Metadata Signing

Metadata signing allows sending signature of pending Repository Service for TUF
(RSTUF) role metadata to an existing RSTUF API deployment.

The Metadata Signing does the following steps:
- retrieves the metadata pending for signatures from RSTUF API
- selects the metadata role for signing
- loads the private key for signing

After loading the key it will sign the role metadata and send the request to
the RSTUF API with the signature.
"""


@admin.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """


def _create_keys_table(
    keys: List[Dict[str, Any]], offline_keys: bool, is_minimal: bool
) -> table.Table:
    """Gets a new keys table."""
    keys_table: table.Table
    if is_minimal:
        keys_table = table.Table(box=box.MINIMAL)
    else:
        keys_table = table.Table()

    keys_table.add_column("Id", justify="center")
    keys_table.add_column("Name/Tag", justify="center")
    keys_table.add_column("Key Type", justify="center")
    keys_table.add_column("Storage", justify="center")
    keys_table.add_column("Public Value", justify="center")

    keys_location: str
    if offline_keys:
        keys_location = "[bright_blue]Offline[/]"
    else:
        keys_location = "[green]Online[/]"

    for key in keys:
        keys_table.add_row(
            f"[yellow]{key['keyid']}",
            f'[yellow]{key["name"]}',
            key["keytype"],
            keys_location,
            f'[yellow]{key["keyval"]["public"]}',
        )

    return keys_table


def _print_root_info(root_info: MetadataInfo):
    root_table = table.Table()
    root_table.add_column("Root", justify="left", vertical="middle")
    root_table.add_column("KEYS", justify="center", vertical="middle")
    number_of_keys = len(root_info.keys)

    root_keys_table = _create_keys_table(root_info.keys, True, True)

    root_table.add_row(
        (
            f"\nNumber of Keys: [yellow]{number_of_keys}[/]"
            f"\nThreshold: [yellow]{root_info.threshold}[/]"
            f"\nRoot Expiration: [yellow]{root_info.expiration_str}[/]"
        ),
        root_keys_table,
    )

    console.print("\n", root_table)
    console.print("\n")


def _get_key(role: str) -> RSTUFKey:
    key_type = prompt.Prompt.ask(
        f"\nChoose [cyan]{role}[/] key type",
        choices=KeyType.get_all_members(),
        default=KeyType.KEY_TYPE_ED25519.value,
    )
    filepath = prompt.Prompt.ask(
        f"Enter the [cyan]{role}[/]`s private key [green]path[/]"
    )
    colored_role = click.style(role, fg="cyan")
    colored_pass = click.style("password", fg="green")
    password = click.prompt(
        f"Enter the {colored_role}`s private key {colored_pass}",
        hide_input=True,
    )

    return load_key(filepath, key_type, password, "")


def _is_valid_current_key(
    keyid: str, root_info: MetadataInfo, already_loaded_keyids: List[str]
) -> bool:
    """Verify that key with `keyid` have been used to sign the current root"""
    if keyid in already_loaded_keyids:
        console.print(
            ":cross_mark: [red]Failed[/]: You already loaded this key",
            width=100,
        )
        return False

    if not root_info.is_keyid_used(keyid):
        console.print(
            (
                ":cross_mark: [red]Failed[/]: This key has not been used "
                "to sign current root metadata",
            ),
            width=100,
        )
        return False

    return True


def _current_md_keys_validation(root_info: MetadataInfo):
    """
    Authorize user by loading current root threshold number of root keys
    used for signing the current root metadata.
    """
    console.print(markdown.Markdown(AUTHORIZATION), width=100)
    threshold = root_info.threshold
    console.print(f"You will need to load {threshold} key(s).")
    loaded: List[str] = []
    key_count = 0
    while key_count < root_info.threshold:
        console.print(
            f"You will enter information for key {key_count} of {threshold}"
        )
        root_key: RSTUFKey = _get_key(Root.type)
        if root_key.error:
            console.print(f"Failed loading key {key_count} of {threshold}")
            console.print(root_key.error)
            continue

        keyid = root_key.key["keyid"]
        if not _is_valid_current_key(keyid, root_info, loaded):
            continue

        key_count += 1
        loaded.append(keyid)
        root_info.save_current_md_key(root_key)
        console.print(
            ":white_check_mark: Key "
            f"{key_count}/{threshold} [green]Verified[/]"
        )

    console.print("\n[green]Authorization is successful [/]\n", width=100)


def _keys_removal(root_info: MetadataInfo):
    """Asking the user if they want to remove any of the root keys"""
    while True:
        if len(root_info.keys) < 1:
            console.print("No keys are left for removal.")
            break

        keys_table = _create_keys_table(root_info.keys, True, False)
        console.print("Here are the current root keys:")
        console.print(keys_table)
        console.print("\n")

        key_removal = prompt.Confirm.ask("Do you want to remove a key")
        if not key_removal:
            break

        name = prompt.Prompt.ask(
            "[green]Name/Tag/ID prefix[/] of the key to remove"
        )
        if not root_info.remove_key(name):
            console.print(
                "\n", f":cross_mark: [red]Failed[/]: key {name} is not in root"
            )
            continue

        console.print(f"Key with name/tag [yellow]{name}[/] removed\n")


def _keys_additions(root_info: MetadataInfo):
    while True:
        # Get all signing keys that are still inside the new root.
        keys: List[Dict[str, Any]] = []
        all_keys = root_info.keys
        for signing_keyid, signing_key in root_info.signing_keys.items():
            if any(signing_keyid == key["keyid"] for key in all_keys):
                keys.append(signing_key.to_dict())

        keys_table = _create_keys_table(keys, True, False)
        console.print("\nHere are the keys that will be used for signing:")
        console.print(keys_table)
        signing_keys_needed = root_info.new_signing_keys_required()
        if signing_keys_needed < 1:
            agree = prompt.Confirm.ask("\nDo you want to add a new key?")
            if not agree:
                return
        else:
            console.print(f"You must add {signing_keys_needed} more key(s)")

        root_key: RSTUFKey = _get_key(Root.type)
        if root_key.error:
            console.print(root_key.error)
            continue

        if root_key.key["keyid"] == root_info.online_key["keyid"]:
            console.print(
                ":cross_mark: [red]Failed[/]: This is the current online key. "
                "Cannot be added"
            )
            continue

        if root_info.is_keyid_used(root_key.key["keyid"]):
            console.print(":cross_mark: [red]Failed[/]: Key is already used")
            continue

        root_key.name = prompt.Prompt.ask(
            "[Optional] Give a [green]name/tag[/] to the key"
        )

        root_info.add_key(root_key)


def _get_positive_int_input(msg: str, input_name: str, default: Any) -> int:
    input: int = 0
    while True:
        input = prompt.IntPrompt.ask(msg, default=default, show_default=True)
        if input >= 1:
            return input

        console.print(f"{input_name} must be at least 1")


def _modify_expiration(root_info: MetadataInfo):
    console.print(markdown.Markdown(EXPIRY_CHANGES_MSG), width=100)
    console.print("\n")
    change: bool
    while True:
        console.print(
            f"Current root expiration: [cyan]{root_info.expiration_str}[/]",
            highlight=False,  # disable built-in rich highlight
        )
        if root_info.expiration < (datetime.now() + timedelta(days=1)):
            console.print("Root root has expired - expiration must be extend")
            change = True

        else:
            change = prompt.Confirm.ask(
                "Do you want to extend the [cyan]root's expiration[/]?"
            )

        if not change:
            console.print("Skipping root expiration changes")
            return
        else:
            m = "Days to extend [cyan]root's expiration[/] starting from today"
            bump = _get_positive_int_input(m, "Expiration extension", 365)
            new_expiry = datetime.now() + timedelta(days=bump)
            new_exp_str = new_expiry.strftime("%Y-%b-%d")
            agree = prompt.Confirm.ask(
                f"New root expiration: [cyan]{new_exp_str}[/]. Do you agree?"
            )
            if agree:
                root_info.expiration = new_expiry
                return


def _modify_root_keys(root_info: MetadataInfo):
    """Modify root keys"""
    console.print(markdown.Markdown(ROOT_KEYS_CHANGES_MSG), width=100)
    console.print("\n")

    while True:
        change = prompt.Confirm.ask(
            "Do you want to modify [cyan]root[/] keys?"
        )
        if not change:
            console.print("Skipping further root keys changes")
            break

        msg = "\nWhat should be the [cyan]root[/] role [green]threshold?[/]"
        root_info.threshold = _get_positive_int_input(
            msg, "Threshold", root_info.threshold
        )

        console.print(markdown.Markdown(ROOT_KEYS_REMOVAL_MSG), width=100)
        _keys_removal(root_info)

        console.print(markdown.Markdown(ROOT_KEY_ADDITIONS_MSG), width=100)
        _keys_additions(root_info)

        console.print("\nHere is the current content of root:")

        _print_root_info(root_info)


def _modify_online_key(root_info: MetadataInfo):
    console.print(markdown.Markdown(ONLINE_KEY_CHANGE), width=100)
    while True:
        online_key_table = _create_keys_table(
            [root_info.online_key], False, False
        )
        console.print("\nHere is the information for the current online key:")
        console.print("\n")
        console.print(online_key_table)
        console.print("\n")
        change = prompt.Confirm.ask(
            "Do you want to change the [cyan]online key[/]?"
        )
        if not change:
            console.print("Skipping further online key changes")
            break

        online_key: RSTUFKey = _get_key("online")
        if online_key.error:
            console.print(online_key.error)
            continue

        if online_key.key["keyid"] == root_info.online_key["keyid"]:
            console.print(
                ":cross_mark: [red]Failed[/]: New online key and current match"
            )
            continue

        if root_info.is_keyid_used(online_key.key["keyid"]):
            console.print(
                ":cross_mark: [red]Failed[/]: Key matches one of the root keys"
            )
            continue

        online_key.name = prompt.Prompt.ask(
            "[Optional] Give a [green]name/tag[/] to the key"
        )

        root_info.change_online_key(online_key)


@metadata.command()  # type: ignore
@click.option(
    "--current-root-uri",
    help="URL or local path to the current root.json file.",
    required=False,
)
@click.option(
    "-f",
    "--file",
    "file",
    default="metadata-update-payload.json",
    help="Generate specific JSON payload file",
    show_default=True,
    required=False,
)
@click.option(
    "-u",
    "--upload",
    help=(
        "Upload existent payload 'file'. "
        "Optional '-f/--file' to use non default file name."
    ),
    required=False,
    is_flag=True,
)
@click.option(
    "--run-ceremony",
    help=(
        "When '--upload' is set this flag can be used to run the ceremony "
        "and the result will be uploaded."
    ),
    default=False,
    show_default=True,
    required=False,
    is_flag=True,
)
@click.option(
    "-s",
    "--save",
    help=(
        "Save a copy of the metadata locally. This option saves the JSON "
        "metadata update payload file in the current directory."
    ),
    default=False,
    show_default=True,
    is_flag=True,
)
@click.option(
    "--upload-server",
    help="[when using '--auth'] Upload to RSTUF API Server address. ",
    required=False,
    hidden=True,
)
@click.pass_context
def update(
    context,
    current_root_uri: str,
    file: str,
    upload: bool,
    run_ceremony: bool,
    save: bool,
    upload_server: str,
) -> None:
    """
    Start a new metadata update ceremony.
    """
    settings = context.obj["settings"]
    if upload and not run_ceremony:
        # Sever authentication or setup
        if settings.AUTH and not upload_server:
            raise click.ClickException(
                "Requires '--upload-server' when using '--auth'. "
                "Example: --upload-server https://rstuf-api.example.com"
            )
        if upload_server:
            settings.SERVER = upload_server

        console.print(
            f"Uploading existing metadata update payload {file} to "
            f"{settings.SERVER}"
        )
        payload = load_payload(file)

        task_id = send_payload(
            settings=settings,
            url=URL.metadata.value,
            payload=payload,
            expected_msg="Metadata update accepted.",
            command_name="Metadata Update",
        )
        task_status(task_id, settings, "Metadata Update status: ")
        console.print(f"Existing payload {file} sent")

        return

    console.print(markdown.Markdown(INTRODUCTION), width=100)
    if save or not upload:
        console.print(f"\nThis ceremony will generate a new {file} file.")
    console.print("\n")
    NOTICE = (
        "**NOTICE: This is an alpha feature and will get updated over time!**"
    )
    console.print(markdown.Markdown(NOTICE), width=100)
    console.print("\n")

    if current_root_uri is None:
        current_root_uri = prompt.Prompt.ask(
            "[cyan]File name or URL[/] to the current root metadata"
        )
        console.print("\n")
    try:
        root_md: Metadata = get_md_file(current_root_uri)
        root_info: MetadataInfo = MetadataInfo(root_md)
    except StorageError:
        raise click.ClickException(
            f"Cannot fetch/load current root {current_root_uri}"
        )
    except DeserializationError:
        raise click.ClickException("Metadata is invalid JSON file")

    console.print(markdown.Markdown(CURRENT_ROOT_INFO), width=100)

    _print_root_info(root_info)

    _current_md_keys_validation(root_info)

    _modify_expiration(root_info)

    _modify_root_keys(root_info)

    _modify_online_key(root_info)

    console.print(markdown.Markdown("## Payload Generation"))

    if root_info.has_changed():
        # There are one or more changes to the root metadata file.
        payload = root_info.generate_payload()
        # Save if the users asks for it or if the payload won't be uploaded.
        if save or not upload:
            save_payload(file, payload)
            console.print(f"File {file} successfully generated")

        if upload:
            task_id = send_payload(
                settings=settings,
                url=URL.metadata.value,
                payload=payload,
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update",
            )
            task_status(task_id, settings, "Metadata Update status: ")

        console.print("Ceremony done. 🔐 🎉. Root metadata update completed.")

    else:
        # There are no changes made to the root metadata file.
        console.print("\nNo file will be generated as no changes were made\n")


def _get_pending_roles(
    settings: Any, api_url: Optional[str]
) -> Dict[str, Any]:
    if settings.AUTH is False and api_url is None:
        api_url = prompt.Prompt.ask("\n[cyan]API[/] URL address")
        settings.SERVER = api_url

    headers = get_headers(settings)
    response = request_server(
        settings.SERVER, URL.metadata_sign.value, Methods.get, headers=headers
    )
    if response.status_code != 200:
        raise click.ClickException(
            f"Failed to retrieve metadata for signing. Error: {response.text}"
        )

    response_data: Dict[str, Any] = response.json().get("data")
    if response_data is None:
        raise click.ClickException(response.text)

    pending_roles: Dict[str, Any] = response_data.get("metadata", {})
    if len(pending_roles) == 0:
        raise click.ClickException("No metadata available for signing")

    return pending_roles


def _get_signing_key(role_info: MetadataInfo) -> RSTUFKey:
    pending_keys: List = []
    for key_id in role_info._new_md.signed.roles[Root.type].keyids:
        if key_id not in role_info._new_md.signatures:
            pending_keys.append(role_info._new_md.signed.keys[key_id])

    sign_key_name = prompt.Prompt.ask(
        "\nChoose a private key to load",
        choices=[
            signing_key.unrecognized_fields.get("name", signing_key.keyid[:7])
            for signing_key in pending_keys
        ],
    )

    while True:
        rstuf_key = _get_key(sign_key_name)
        if rstuf_key.error:
            console.print(rstuf_key.error)
            retry = prompt.Confirm.ask(
                f"\nRetry to load the key {sign_key_name}?"
            )
            if not retry:
                console.print("Aborted.")
                sys.exit(0)
        else:
            break

    rstuf_key_id = rstuf_key.key["keyid"]

    current_role_key = role_info._new_md.signed.keys[rstuf_key_id]
    current_role_key_name = current_role_key.unrecognized_fields.get(
        "name", current_role_key.keyid[:7]
    )
    if current_role_key_name != sign_key_name:
        raise click.ClickException(f"Loaded key is not '{sign_key_name}'")

    return rstuf_key


def _sign_metadata(role_info: MetadataInfo, rstuf_key: RSTUFKey) -> Signature:
    signer = role_info.get_signer(rstuf_key)
    try:
        signature = role_info._new_md.sign(signer)
    except UnsignedMetadataError as err:
        raise click.ClickException("Problem signing the metadata") from err

    return signature


@metadata.command()
@click.option(
    "--api-url",
    help="URL to an RSTUF API.",
    required=False,
)
@click.pass_context
def sign(context, api_url: Optional[str]) -> None:
    """
    Start metadata signature.
    """
    console.print(markdown.Markdown(METADATA_SIGNING), width=100)

    settings = context.obj["settings"]

    pending_roles = _get_pending_roles(settings, api_url)
    rolename = prompt.Prompt.ask(
        "\nChoose a metadata to sign", choices=[role for role in pending_roles]
    )
    role_info = MetadataInfo(Metadata.from_dict(pending_roles[rolename]))
    console.print(
        f"Signing [cyan]{rolename}[/] version "
        f"{role_info._new_md.signed.version}"
    )

    rstuf_key = _get_signing_key(role_info)
    signature = _sign_metadata(role_info, rstuf_key)

    payload = {"role": rolename, "signature": signature.to_dict()}
    console.print("\nSending signature")
    task_id = send_payload(
        settings,
        URL.metadata_sign.value,
        payload,
        "Metadata sign accepted.",
        "Metadata sign",
    )
    task_status(task_id, settings, "Metadata sign status:")
    console.print("\nMetadata Signed! 🔑\n")
