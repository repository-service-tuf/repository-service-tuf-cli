# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import click
from rich import box, markdown, prompt, table
from typing import Any, List
from tuf.api.metadata import Metadata, Root
from securesystemslib.exceptions import StorageError

from repository_service_tuf.cli import console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.cli.admin.ceremony import _load_key, _save_payload

from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers.tuf import (
    Roles,
    RSTUFKey,
    RootInfo
)

INTRODUCTION = """
# Metadata Update

The "rstuf admin metadata update" command is created for cases when a user
wants to:
- change all roles expiration policy
- modify the keys used for signing (no matter if root keys or the
online key),
- change the root threshold value

The result of this ceremony will be a new root metadata file.
"""

CURRENT_ROOT_INFO = """
# Current Root Content

Before deciding what you want to update it's recommended that you
get familiar with the current state of the root metadata file.
"""

AUTHORIZATION = """
# Authorization

Before continuing you are required to authorize yourself by using the current
root keys.

In order to complete the authorization you will be asked to provide information
about one or more keys used to sign the current root metadata.
You will need local access to the keys as well as their corresponding
passwords.

The number of keys that are required is based on the "threshold" of keys used
to sign the current root metadata.
"""

EXPIRY_CHANGES_MSG = """
# Expiration Policy Changes

You will be given the opportunity to change the expiration policy value of each
of the roles.
For all roles (except the root role) this value is used to automatically bump
their corresponding expiration date.

Note: the root expiration is bumped ONLY during the metadata update ceremony.
"""

ROOT_CHANGES_MSG = """
# Root Metadata Changes

You are starting the root metadata changes procedure.

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

ONLINE_KEY_CHANGE= """
# Online Key Change

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


def _get_curr_root(curr_root_uri: str) -> RootInfo:
    root_split = curr_root_uri.split("://")
    curr_root_md: Metadata[Root]
    if len(root_split) > 1 and root_split[0] in ["http", "https"]:
        console.print(f"Fetching current root from: {curr_root_uri}")
    else:
        curr_root_md = Metadata.from_file(curr_root_uri)

    return RootInfo.from_md(curr_root_md)


def _create_keys_table(
    curr_root: RootInfo, is_online_key_table: bool, is_minimal: bool
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
        keys = [curr_root.online_key]
    else:
        key_location = "[bright_blue]Offline[/]"
        keys = list(curr_root.root_keys.values())

    for key in keys:
        keys_table.add_row(
            f'[yellow]{key.key["keyid"]}',
            f"[yellow]{key.name}",
            key.key["keytype"],
            key_location,
            f'[yellow]{key.key["keyval"]["public"]}',
        )

    return keys_table


def _print_curr_root(curr_root: RootInfo):
    root_table = table.Table()
    root_table.add_column("Root", justify="left", vertical="middle")
    root_table.add_column("KEYS", justify="center", vertical="middle")
    number_of_keys = len(curr_root.root_keys)
    expiration = curr_root.expiration.strftime("%Y-%b-%d")

    root_keys_table = _create_keys_table(
        curr_root, is_online_key_table=False, is_minimal=True
    )

    root_table.add_row(
        (
            f"Role: [cyan]{Root.type}[/]"
            f"\nNumber of Keys: [yellow]{number_of_keys}[/]"
            f"\nThreshold: [yellow]{curr_root.threshold}[/]"
            f"\nRole Expiration: [yellow]{expiration}[/]"
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
    password = prompt.Prompt.ask(
        f"Enter the [cyan]{role}[/]`s private key [green]password[/]",
        password=True,
    )

    return _load_key(filepath, key_type, password, "")

def _is_valid_current_key(
    keyid: str, current_root: RootInfo, already_loaded_keyids: List[str]
) -> False:
    """Verify that key with `keyid` have been used to sign the current root"""
    if keyid in already_loaded_keyids:
        console.print(
            ":cross_mark: [red]Failed[/]: You already loaded this key",
            width=100
        )
        return False

    if not current_root.is_keyid_used(keyid):
        console.print(
            (
                ":cross_mark: [red]Failed[/]: This key has not been used "
                "to sign current root metadata",
            ),
            width=100
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

    console.print("[green]Authorization is successful [/]\n", width=100)


def _keys_removal(current_root: RootInfo):
    """Asking the user if he wants to remove any of the root keys"""
    while True:
        keys_table = _create_keys_table(
            current_root, is_online_key_table=False, is_minimal=False
        )
        console.print("Here are the current root keys:")
        console.print(keys_table)
        console.print("\n")

        key_removal = prompt.Confirm.ask(f"Do you want to remove a key")
        if not key_removal:
            break

        name =  prompt.Prompt.ask("[green]Name/Tag[/] of the key to remove")
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
        if not response:
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


def _modify_expiration_policy(current_root: RootInfo):
    console.print(markdown.Markdown(EXPIRY_CHANGES_MSG), width=100)
    expiry_table = table.Table()
    expiry_table.add_column("Role", justify="center")
    expiry_table.add_column("Expiration Policy", justify="center")
    for role in Roles:
        msg_prefix = f"\n[cyan]Expiration policy for {role.value}[/] -"
        msg_suffix = "number of days to automatically bump expiration"
        if role == Roles.ROOT:
            msg_suffix = "number of days to bump expiration"

        msg = f"{msg_prefix} {msg_suffix}"
        default = current_root.expirations[role]
        expiry_bump = _get_positive_int_input(
            msg, "Expiration policy days", default
        )
        current_root.save_expiry(role, expiry_bump)
        expiry_table.add_row(
            f"[cyan]{role.value}", f"[yellow]{str(expiry_bump)}"
        )

    console.print("\nHere is summarization of the expiration policy changes:")
    console.print("\n", expiry_table)


def _modify_root_md(current_root: RootInfo):
    """Update root metadata file"""
    console.print(markdown.Markdown(ROOT_CHANGES_MSG), width=100)
    console.print("\n")

    while True:
        change = prompt.Confirm.ask(
            "Do you want to change the [cyan]root[/] metadata?"
        )
        if not change:
            console.print("Skipping further root metadata changes.")
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

        _print_curr_root(current_root)


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
        if not change:
            console.print("Skipping further online key changes.")
            break

        online_key: RSTUFKey = _get_key(Root.type)
        if online_key.error:
            console.print(f":cross_mark: [red]Failed[/]: {online_key.error}")
            continue

        if online_key == current_root.online_key:
            console.print(
                ":cross_mark: [red]Failed[/]: This is the current online key. "
                "Cannot be added"
            )
            continue

        if current_root.is_keyid_used(online_key.key["keyid"]):
            console.print(":cross_mark: [red]Failed[/]: Key is already used")
            continue

        online_key.name = prompt.Prompt.ask(
            "[Optional] Give a [green]name/tag[/] to the key"
        )

        current_root.change_online_key(online_key)


# ADD OPTION TO UPLOAD NEW ROOT CONTENT
@metadata.command()
@click.option(
    "--current-root",
    help="URL or local path to the current root.json file.",
    required=True,
)
@click.option(
    "-f",
    "--file",
    "file",
    default="payload.json",
    help=(
        "Generate specific JSON payload file"
    ),
    show_default=True,
    required=False,
)
@click.pass_context
def update(context, current_root: str, file: str) -> None:
    """
    Start a new metadata update ceremony.
    """
    try:
        curr_root: RootInfo = _get_curr_root(current_root)
    except StorageError:
        raise click.ClickException(
            f"Cannot fetch/load current root {current_root}"
        )

    console.print(markdown.Markdown(INTRODUCTION), width=100)

    console.print(markdown.Markdown(CURRENT_ROOT_INFO), width=100)

    _print_curr_root(curr_root)

    _current_root_keys_validation(curr_root)

    _modify_expiration_policy(curr_root)

    _modify_root_md(curr_root)

    _modify_online_key(curr_root)

    console.print(markdown.Markdown("## Payload Generation"))

    payload = curr_root.generate_payload()
    _save_payload(file, payload)
    console.print(f"Payload successfully generated and saved in file {file}")
