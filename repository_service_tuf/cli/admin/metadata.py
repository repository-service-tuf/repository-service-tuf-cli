# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from datetime import datetime, timedelta
from typing import Any, List

from rich import box, markdown, prompt, table
from securesystemslib.exceptions import StorageError  # type: ignore
from tuf.api.metadata import Metadata, Root
from tuf.api.serialization import DeserializationError

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    get_md_file,
    send_payload,
    task_status,
)
from repository_service_tuf.helpers.tuf import (
    RootInfo,
    RSTUFKey,
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


@admin.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """


def _create_keys_table(
    root_info: RootInfo, is_online_key_table: bool, is_minimal: bool
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

    key_location: str
    keys: List[RSTUFKey] = []
    if is_online_key_table:
        key_location = "[green]Online[/]"
        keys = [root_info.online_key]
    else:
        key_location = "[bright_blue]Offline[/]"
        keys = list(root_info.root_keys.values())

    for key in keys:
        keys_table.add_row(
            f'[yellow]{key.key["keyid"]}',
            f"[yellow]{key.name}",
            key.key["keytype"],
            key_location,
            f'[yellow]{key.key["keyval"]["public"]}',
        )

    return keys_table


def _print_root_info(root_info: RootInfo):
    root_table = table.Table()
    root_table.add_column("Root", justify="left", vertical="middle")
    root_table.add_column("KEYS", justify="center", vertical="middle")
    number_of_keys = len(root_info.root_keys)

    root_keys_table = _create_keys_table(
        root_info, is_online_key_table=False, is_minimal=True
    )

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
    keyid: str, current_root: RootInfo, already_loaded_keyids: List[str]
) -> bool:
    """Verify that key with `keyid` have been used to sign the current root"""
    if keyid in already_loaded_keyids:
        console.print(
            ":cross_mark: [red]Failed[/]: You already loaded this key",
            width=100,
        )
        return False

    if not current_root.is_keyid_used(keyid):
        console.print(
            (
                ":cross_mark: [red]Failed[/]: This key has not been used "
                "to sign current root metadata",
            ),
            width=100,
        )
        return False

    return True


def _current_root_keys_validation(current_root: RootInfo):
    """
    Authorize user by loading current root threshold number of root keys
    used for signing the current root metadata.
    """
    console.print(markdown.Markdown(AUTHORIZATION), width=100)
    threshold = current_root.threshold
    console.print(f"You will need to load {threshold} key(s).")
    loaded: List[str] = []
    key_count = 0
    while key_count < current_root.threshold:
        console.print(
            f"You will enter information for key {key_count} of {threshold}"
        )
        root_key: RSTUFKey = _get_key(Root.type)
        if root_key.error:
            console.print(root_key.error)
            try_again = prompt.Confirm.ask("Try again?")
            if try_again:
                continue
            else:
                raise click.ClickException(
                    f"Failed authorization. Required: {threshold}, loaded"
                    f"{len(loaded)} keys"
                )

        keyid = root_key.key["keyid"]
        if not _is_valid_current_key(keyid, current_root, loaded):
            continue

        key_count += 1
        loaded.append(keyid)
        current_root.save_current_root_key(root_key)
        console.print(
            ":white_check_mark: Key "
            f"{key_count}/{threshold} [green]Verified[/]"
        )

    console.print("\n[green]Authorization is successful [/]\n", width=100)


def _keys_removal(current_root: RootInfo):
    """Asking the user if he wants to remove any of the root keys"""
    while True:
        keys_table = _create_keys_table(
            current_root, is_online_key_table=False, is_minimal=False
        )
        console.print("Here are the current root keys:")
        console.print(keys_table)
        console.print("\n")

        key_removal = prompt.Confirm.ask("Do you want to remove a key")
        if key_removal is False:
            break

        name = prompt.Prompt.ask(
            "[green]Name/Tag/ID prefix[/] of the key to remove"
        )
        if not current_root.remove_key(name):
            console.print(
                "\n", f":cross_mark: [red]Failed[/]: key {name} is not in root"
            )
        else:
            console.print(f"Key with name/tag [yellow]{name}[/] removed\n")
            if len(current_root.root_keys) < 1:
                console.print("No keys are left for removal.")
                break


def _keys_additions(current_root: RootInfo):
    root_threshold = current_root.threshold
    console.print(f"You need to have at least [cyan]{root_threshold}[/] keys.")
    while True:
        keys_table = _create_keys_table(
            current_root, is_online_key_table=False, is_minimal=False
        )
        console.print("\nHere are the current root keys:")
        console.print(keys_table)
        response = prompt.Confirm.ask("\nDo you want to add a new key?")
        if response is False:
            keys_amount = len(current_root.root_keys)
            if keys_amount < root_threshold:
                remaining_keys = root_threshold - keys_amount
                console.print(
                    f"You need to add an additional {remaining_keys} keys"
                )
                abort = prompt.Confirm.ask(
                    "Do you want to abort the root metadata update",
                )
                if abort:
                    raise click.ClickException(
                        "Not enough keys to fulfill the threshold requirement"
                    )
                else:
                    continue
            else:
                break

        root_key: RSTUFKey = _get_key(Root.type)
        if root_key.error:
            console.print(f":cross_mark: [red]Failed[/]: {root_key.error}")
            continue

        if root_key == current_root.online_key:
            console.print(
                ":cross_mark: [red]Failed[/]: This is the current online key. "
                "Cannot be added"
            )
            continue

        if current_root.is_keyid_used(root_key.key["keyid"]):
            console.print(":cross_mark: [red]Failed[/]: Key is already used")
            continue

        root_key.name = prompt.Prompt.ask(
            "[Optional] Give a [green]name/tag[/] to the key"
        )

        current_root.add_key(root_key)


def _get_positive_int_input(msg: str, input_name: str, default: Any) -> int:
    input: int = 0
    while input < 1:
        input = prompt.IntPrompt.ask(msg, default=default, show_default=True)
        if input < 1:
            console.print(f"{input_name} must be at least 1")
            continue

    return input


def _modify_expiration(current_root: RootInfo):
    console.print(markdown.Markdown(EXPIRY_CHANGES_MSG), width=100)
    console.print("\n")
    while True:
        console.print(
            f"Current root expiration: [cyan]{current_root.expiration_str}[/]",
            highlight=False,  # disable built-in rich highlight
        )
        change = prompt.Confirm.ask(
            "Do you want to extend the [cyan]root's expiration[/]?"
        )
        if change is False:
            if current_root.expiration < (datetime.now() + timedelta(days=1)):
                console.print(
                    "You must extend root's expiration - root has expired"
                )
                continue
            else:
                console.print("Skipping root expiration changes")
                return
        else:
            break

    msg = "Days to extend [cyan]root's expiration[/] starting from today"
    while True:
        expiry_bump = _get_positive_int_input(msg, "Expiration extension", 365)
        new_expiry = datetime.now() + timedelta(days=expiry_bump)
        new_exp_str = new_expiry.strftime("%Y-%b-%d")
        agree = prompt.Confirm.ask(
            f"New root expiration: [cyan]{new_exp_str}[/]. Do you agree?"
        )
        if agree is False:
            continue
        else:
            current_root.expiration = new_expiry
            break


def _modify_root_keys(current_root: RootInfo):
    """Modify root keys"""
    console.print(markdown.Markdown(ROOT_KEYS_CHANGES_MSG), width=100)
    console.print("\n")

    while True:
        change = prompt.Confirm.ask(
            "Do you want to modify [cyan]root[/] keys?"
        )
        if change is False:
            console.print("Skipping further root keys changes")
            break

        msg = "\nWhat should be the [cyan]root[/] role [green]threshold?[/]"
        current_root.threshold = _get_positive_int_input(
            msg, "threshold", current_root.threshold
        )

        console.print(markdown.Markdown(ROOT_KEYS_REMOVAL_MSG), width=100)
        _keys_removal(current_root)

        console.print(markdown.Markdown(ROOT_KEY_ADDITIONS_MSG), width=100)
        _keys_additions(current_root)

        console.print("\nHere is the current content of root:")

        _print_root_info(current_root)


def _modify_online_key(current_root: RootInfo):
    console.print(markdown.Markdown(ONLINE_KEY_CHANGE), width=100)
    while True:
        online_key_table = _create_keys_table(
            current_root, is_online_key_table=True, is_minimal=False
        )
        console.print("\nHere is the information for the current online key:")
        console.print("\n")
        console.print(online_key_table)
        console.print("\n")
        change = prompt.Confirm.ask(
            "Do you want to change the [cyan]online key[/]?"
        )
        if change is False:
            console.print("Skipping further online key changes")
            break

        online_key: RSTUFKey = _get_key(Root.type)
        if online_key.error:
            console.print(f":cross_mark: [red]Failed[/]: {online_key.error}")
            continue

        if online_key == current_root.online_key:
            console.print(
                ":cross_mark: [red]Failed[/]: The new online key is the same "
                " as the current online key"
            )
            continue

        if current_root.is_keyid_used(online_key.key["keyid"]):
            console.print(
                ":cross_mark: [red]Failed[/]: Key matches one of the root keys"
            )
            continue

        online_key.name = prompt.Prompt.ask(
            "[Optional] Give a [green]name/tag[/] to the key"
        )

        current_root.change_online_key(online_key)


@metadata.command()
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
        if settings.AUTH is True and upload_server is None:
            raise click.ClickException(
                "Requires '--upload-server' when using '--auth'. "
                "Example: --upload-server https://rstuf-api.example.com"
            )
        elif upload_server:
            settings.SERVER = upload_server

        console.print(
            f"Uploading existing metadata update payload {file} to "
            f"{settings.SERVER}"
        )
        payload = load_payload(file)

        task_id = send_payload(
            settings=settings,
            url=URL.metadata.value,
            method=Methods.post,
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
        root_info: RootInfo = RootInfo.from_md(root_md)
    except StorageError:
        raise click.ClickException(
            f"Cannot fetch/load current root {current_root_uri}"
        )
    except DeserializationError:
        raise click.ClickException("Metadata is invalid JSON file")

    console.print(markdown.Markdown(CURRENT_ROOT_INFO), width=100)

    _print_root_info(root_info)

    _current_root_keys_validation(root_info)

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
                method=Methods.post,
                payload=payload,
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update",
            )
            task_status(task_id, settings, "Metadata Update status: ")

        console.print("Ceremony done. 🔐 🎉. Root metadata update completed.")

    else:
        # There are no changes made to the root metadata file.
        console.print("\nNo file will be generated as no changes were made\n")
