# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

#
# Ceremony
#
import json
import os
from typing import Any, Dict, Generator, Optional

from rich import box, markdown, prompt, table  # type: ignore
from rich.console import Console  # type: ignore
from securesystemslib.exceptions import (  # type: ignore
    CryptoError,
    Error,
    FormatError,
    StorageError,
)
from securesystemslib.interface import (  # type: ignore
    KEY_TYPE_ECDSA,
    KEY_TYPE_ED25519,
    KEY_TYPE_RSA,
    import_privatekey_from_file,
)

from repository_service_tuf.cli import click
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.helpers.api_client import (
    URL,
    LazySettings,
    Methods,
    bootstrap_status,
    get_headers,
    request_server,
    task_status,
)
from repository_service_tuf.helpers.tuf import (
    BootstrapSetup,
    Roles,
    RSTUFKey,
    ServiceSettings,
    initialize_metadata,
)

CEREMONY_INTRO = """
# Repository Metadata and Settings for the Repository Service for TUF

Repository Service for TUF (RSTUF) is a system for securing content downloads
from tampering between the repository and the client using The Update Framework
(TUF). More about TUF access https://theupdateframework.io

## Ceremony of signing the TUF Metadata

This process consists of using the metadata settings and signing this metadata,
generating the initial metadata at the end of the process, and optionally
bootstrapping the RSTUF system. See [`rstuf admin ceremony -h`]

This process is done by answering settings definitions, using the **offline
keys** for signing the Root metadata, and providing the **online key** used by
the other metadata roles in RSTUF.
"""

CEREMONY_INTRO_ROLES_RESPONSIBILITIES = """
## Roles and Responsibilities

Repository Service for TUF implements roles and responsibilities based on TUF
top-level roles (root, targets, timestamp, and snapshot) and the delegated hash
bin roles.

The inspiration for Repository Service for TUF is the
[Python Enhancement Proposal 458](https://peps.python.org/pep-0458/).



                       .-------------,
            .--------- |   root *    |-----------.
            |          `-------------'           |
            |                 |                  |
            V                 V                  V
    .-------------,    .-------------,    .-------------,
    |  timestamp  |    |  snapshot   |    |   targets   |
    `-------------'    `-------------'    `-------------'
                                                 .
                                                 .
                                                 .
                             .........................................
                             .                   .                   .
                             .                   .                   .
                             .                   .                   .
                             V                   V                   V
                      .-------------,     .-------------,     .-------------,
                      |  bins 0-X   | ... |  bin A-FF   | ... |  bin X-FF   |
                      `-------------'     `-------------'     `-------------'
    * offline keys

The explanation will follow an example of the Organization Example Inc.

**root**

The root role is the locus of trust for the entire repository. The root role
signs the `root.json` metadata file. This file indicates the authorized keys
for each top-level role, including the root role itself.

Minimum recommended: 2 Keys and a Threshold equal to 1.

Example:
Corp Example Inc will use two keys and a threshold of one. Key Owners:
* CTO (Jimi Hendrix)
* VP of Security (Janis Joplin).

**targets**

The targets role is responsible for indicating which target files are available
from the repository. More precisely, it shares the responsibility of providing
information about the content of updates. The targets role signs `targets.json`
metadata and delegates to the hash bins roles (called bins).

Uses one single online key.

**bins**

The bins role is a target delegated role and is responsible for signing
the target files in the file repositories.

Uses one single online key.

**snapshot**

The snapshot role ensures that clients see a consistent repository state.
It provides repository state information by indicating the latest versions
of the top-level targets (the targets role) and delegated targets
(hash bins roles) metadata files on the repository in `snapshot.json`.

Uses one single online key.

**timestamp**

The timestamp role is responsible for providing information about the
timelines of available updates. Timelines information is made available by
frequently signing a new timestamp.json file with a short expiration time.
This file indicates the latest version of `snapshot.json`.

Uses one single online key,
"""

STEP_1 = """
# STEP 1: Configure the Roles

The TUF root role supports multiple keys and the threshold (quorum of trust)
defines the minimal number of keys required to take actions using the root role.

Reference: [TUF Goals for PKI](https://theupdateframework.github.io/specification/latest/#goals-for-pki)

The TUF roles have an expiration, clients must not trust expired metadata.

Reference: [TUF expires](https://theupdateframework.github.io/specification/latest/#expires)

"""  # noqa

STEP_2 = """
# STEP 2: Load the Online Key

## The Online Key
The online key is the same one provided to the Repository Service for TUF
Workers (RSTUF Worker). This key is responsible for signing the snapshot,
timestamp, targets, and delegated targets (hash bin) roles.

The RSTUF Worker uses this key during the process of managing the metadata.

Note: the ceremony process won't show any password or key content.
"""

STEP_3 = """
# STEP 3: Load Root Keys

## Root Keys
The keys must have a password, and the file must be accessible.

Depending on the organization, each key has an owner, and each owner should
insert the password personally.

Note: the ceremony process won't show any password or key content.
"""

STEP_4 = """
# STEP 4: Validate Configuration

The information below is the configuration done in the previous steps.
Check the number of keys, the threshold/quorum, and the key details.

"""

BINS_DELEGATION_MESSAGE = """

The target metadata file might contain a large number of target files. That's
why the targets role delegates trust to the hash bin roles to reduce the
metadata overhead for clients.

See:
[TUF Specification about succinct hash bin delegation](
    https://github.com/theupdateframework/taps/blob/master/tap15.md
).
"""

HASH_BINS_EXAMPLE = """

Example:
--------

The Organization Example (https://example.com) has all files downloaded
`/downloads` path, meaning https://example.com/downloads/.

Additionally, it has two sub-folders, productA and productB where the clients
can find all files (i.e.: productA-v1.0.tar, productB-v1.0.tar), for productB
it even has a sub-folder, updates where clients can find update files
(i.e.: servicepack-1.tar, servicepack-2.tar).
The organization has decided to use 8 hash bins. Target files will be
uniformly distributed over 8 bins whose names will be "1.bins-0.json",
"1.bins-1.json", ... , "1.bins-7.json".

Now imagine that the organization stores the following files:
- https://example.com/downloads/productA/productA-v1.0.tar
- https://example.com/downloads/productB/productB-v1.0.tar
- https://example.com/downloads/productB/updates/servicepack-1.tar

As we said the targets will be uniformly distributed over the 8 bins no matter
if they are located in the same folder.
In this example here is how they will be distributed:
- "1.bins-0.json" will be responsible for file:
 https://example.com/downloads/productA/productA-v1.0.tar
- "1.bins-1.json" will be responsible for file:
 https://example.com/downloads/productB/productB-v1.0.tar
- "1.bins-5.json" will be responsible for file:
 https://example.com/downloads/productB/updates/servicepack-1.tar
"""

console = Console()


# Define all initial settings
setup = BootstrapSetup(
    expiration={
        Roles.ROOT: 365,
        Roles.TARGETS: 365,
        Roles.SNAPSHOT: 1,
        Roles.TIMESTAMP: 1,
        Roles.BINS: 1,
    },
    services=ServiceSettings(),
    number_of_keys={Roles.ROOT: 2, Roles.TARGETS: 1},
    threshold={
        Roles.ROOT: 1,
        Roles.TARGETS: 1,
    },
    keys={
        Roles.ROOT: [],
        Roles.TARGETS: [],
        Roles.SNAPSHOT: [],
        Roles.TIMESTAMP: [],
        Roles.BINS: [],
    },
    online_key=RSTUFKey(),
)


def _key_already_in_use(key: Dict[str, Any]) -> bool:
    """Check if a key is duplicated, used in a role or the online_key"""
    # verify if the key exists in any role keys
    for role_keys in setup.keys.values():
        if any(
            k
            for k in role_keys
            if (
                key is not None
                and k.key is not None
                and key.get("keyid") == k.key.get("keyid")
            )
        ):
            return True

    # verify if key is used by `online_key`
    if setup.online_key.key is not None and key.get(
        "keyid"
    ) == setup.online_key.key.get("keyid"):
        return True

    return False


def _load_key(
    filepath: str, keytype: str, password: Optional[str]
) -> RSTUFKey:
    try:
        key = import_privatekey_from_file(filepath, keytype, password)
        return RSTUFKey(key=key, key_path=filepath)
    except CryptoError as err:
        return RSTUFKey(
            error=(
                f":cross_mark: [red]Failed[/]: {str(err)} Check the"
                " password, type, etc"
            )
        )

    except (StorageError, FormatError, Error, OSError) as err:
        return RSTUFKey(error=f":cross_mark: [red]Failed[/]: {str(err)}")


def _send_bootstrap(
    settings: LazySettings, bootstrap_payload: Dict[str, Any]
) -> str:
    headers = get_headers(settings)
    response = request_server(
        settings.SERVER,
        URL.bootstrap.value,
        Methods.post,
        bootstrap_payload,
        headers=headers,
    )

    if response.status_code != 202:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )

    response_json = response.json()
    if (
        response_json.get("message") is None
        or response_json.get("message") != "Bootstrap accepted."
    ):
        raise click.ClickException(response.text)

    else:
        if data := response_json.get("data"):
            task_id = data.get("task_id")
            if task_id is None:
                raise click.ClickException(
                    f"Failed to get `task id` {response.text}"
                )
            console.print(f"Bootstrap status: ACCEPTED ({task_id})")

            return task_id
        else:
            raise click.ClickException(
                f"Failed to get task response data {response.text}"
            )


def _load_bootstrap_payload(path: str) -> Dict[str, Any]:
    try:
        with open(path) as payload_data:
            bootstrap_payload = json.load(payload_data)
    except OSError as err:
        raise click.ClickException(f"Error to load {path}. {str(err)}")

    return bootstrap_payload


def _save_bootstrap_payload(file: str, bootstrap_payload: Dict[str, Any]):
    try:
        with open(file, "w") as f:
            f.write(json.dumps(bootstrap_payload, indent=2))
    except OSError as err:
        raise click.ClickException(f"Failed to save {file}. {str(err)}")


def _configure_role_target():
    console.print("\n")
    console.print(markdown.Markdown(BINS_DELEGATION_MESSAGE), width=100)
    show_example = prompt.Confirm.ask("Show example?", default="y")
    if show_example:
        with console.pager(links=True):
            console.print(markdown.Markdown(HASH_BINS_EXAMPLE), width=100)

    setup.services.number_of_delegated_bins = prompt.IntPrompt.ask(
        "\nChoose the number of delegated hash bin roles",
        default=256,
        choices=[str(2**i) for i in range(1, 15)],  # choices must be str
        show_default=True,
        show_choices=True,
    )

    targets_base_url = click.prompt(
        "\nWhat is the targets base URL? (i.e.: "
        "https://www.example.com/downloads/)"
    )
    if targets_base_url.endswith("/") is False:
        targets_base_url = targets_base_url + "/"

    setup.services.targets_base_url = targets_base_url


def _configure_role_root():
    setup.number_of_keys[Roles.ROOT] = prompt.IntPrompt.ask(
        (
            f"What is the [green]number of keys[/] for "
            f"the [cyan]{Roles.ROOT.value}[/] role?"
        ),
        default=setup.number_of_keys[Roles.ROOT],
        show_default=True,
    )
    if setup.number_of_keys[Roles.ROOT] > 1:
        setup.threshold[Roles.ROOT] = prompt.IntPrompt.ask(
            (
                f"What is the key [green]threshold[/] for "
                f"the [cyan]{Roles.ROOT.value}[/] role signing?"
            ),
            default=setup.threshold[Roles.ROOT],
            show_default=True,
        )
    else:
        setup.threshold[Roles.ROOT] = 1
        console.print(
            f"The [green]threshold[/] for [cyan]{Roles.ROOT.value}[/] "
            "is [cyan]1[/] (one) based on the number of keys ([cyan]1[/])."
        )


def _configure_role(role: Roles) -> None:
    console.print(
        markdown.Markdown(f"## {role.value} configuration"), width=100
    )
    setup.expiration[role] = prompt.IntPrompt.ask(
        (
            "\nWhat is the [green]metadata expiration[/] for "
            f"the [cyan]{role.value}[/] role?(Days)"
        ),
        default=setup.expiration[role],
        show_default=True,
    )

    if role == Roles.ROOT:
        _configure_role_root()

    if role == Roles.TARGETS:
        _configure_role_target()


def _configure_keys(
    role: str, number_of_keys: int
) -> Generator[RSTUFKey, None, None]:
    key_count = 1
    while key_count <= number_of_keys:
        key_type = prompt.Prompt.ask(
            f"\nChoose {key_count}/{number_of_keys} [cyan]{role}[/] key type",
            choices=[KEY_TYPE_ED25519, KEY_TYPE_ECDSA, KEY_TYPE_RSA],
            default=KEY_TYPE_ED25519,
        )
        filepath = prompt.Prompt.ask(
            f"Enter {key_count}/{number_of_keys} the "
            f"[cyan]{role}[/]`s private key [green]path[/]"
        )

        password = click.prompt(
            f"Enter {key_count}/{number_of_keys} the "
            f"{role}`s private key password",
            hide_input=True,
        )
        role_key: RSTUFKey = _load_key(filepath, key_type, password)

        if role_key.error:
            console.print(role_key.error)
            try_again = prompt.Confirm.ask("Try again?", default="y")
            if try_again:
                continue
            else:
                raise click.ClickException("Required key not validated.")

        if role_key.key is None or _key_already_in_use(role_key.key) is True:
            console.print(":cross_mark: [red]Failed[/]: Key is duplicated.")
            continue

        yield role_key

        console.print(
            ":white_check_mark: Key "
            f"{key_count}/{number_of_keys} [green]Verified[/]"
        )
        key_count += 1


def _run_user_validation():
    # Tables
    #
    # The table.Table doesn't have a library API to remove/clean the rows, so
    # we call the function to reset/construct it.
    def _init_summary_table(title: str) -> table.Table:
        online_key_table = table.Table()
        online_key_table.add_column(
            f"{title}",
            justify="left",
            vertical="middle",
        )
        return online_key_table

    def _init_keys_table(path: Optional[bool] = True) -> table.Table:
        """Gets a new keys table"""
        keys_table = table.Table(box=box.MINIMAL)
        if path is True:
            keys_table.add_column(
                "path", justify="right", style="cyan", no_wrap=True
            )
        keys_table.add_column("type", justify="center")
        keys_table.add_column("verified", justify="center")
        keys_table.add_column("id", justify="center")

        return keys_table

    # Validations
    #
    # Online Key validation
    while True:
        online_key_table = _init_summary_table("ONLINE KEY SUMMARY")
        keys_table = _init_keys_table()
        keys_table.add_row(
            f"[yellow]{setup.online_key.key_path}[/]",
            "[green]Online[/]",
            ":white_heavy_check_mark:",
            f"[yellow]{setup.online_key.key.get('keyid')}[/]",
        )

        online_key_table.add_row(keys_table)
        console.print("\n", online_key_table)

        confirm_config = prompt.Confirm.ask(
            "\nIs the [cyan]online key[/] configuration correct?"
        )
        if confirm_config is False:
            setup.online_key.key = {}
            setup.online_key.key_path = None
            for key in _configure_keys("ONLINE", 1):
                setup.online_key.key = key.key
                setup.online_key.key_path = key.key_path
        else:
            break

    # Roles validation
    for role in Roles:
        while True:
            role_table = _init_summary_table("ROLE SUMMARY")
            role_table.add_column("KEYS", justify="center", vertical="middle")

            if role == Roles.ROOT:
                keys_table = _init_keys_table()
                for key in setup.keys[Roles.ROOT]:
                    keys_table.add_row(
                        f"[yellow]{key.key_path}[/]",
                        "[bright_blue]Offline[/]",
                        ":white_heavy_check_mark:",
                        key.key.get("keyid"),
                    )

                role_table.add_row(
                    (
                        f"Role: [cyan]{role.value}[/]"
                        f"\nNumber of Keys: [yellow]{len(setup.keys[role])}[/]"
                        f"\nThreshold: [yellow]{setup.threshold[Roles.ROOT]}"
                        "[/]"
                        f"\nRole Expiration: [yellow]{setup.expiration[role]} "
                        "[/]days"
                    ),
                    keys_table,
                )
            else:
                keys_table = _init_keys_table(path=False)
                if setup.online_key.key is not None:
                    keys_table.add_row(
                        "[green]Online[/]",
                        ":white_heavy_check_mark:",
                        setup.online_key.key.get("keyid"),
                    )
                role_table.add_row(
                    (
                        f"Role: [cyan]{role.value}[/]"
                        f"\nRole Expiration: [yellow]{setup.expiration[role]} "
                        "[/]days"
                    ),
                    keys_table,
                )

            if role == Roles.TARGETS:
                base_url = setup.services.targets_base_url
                role_table.add_row(
                    (
                        f"\n[white]Base URL:[/] [yellow]{base_url}[/]"
                        "\n"
                        "\n[orange1]DELEGATIONS[/]"
                        f"\n[aquamarine3]{role.value} -> bins[/]"
                        "\nNumber of bins: "
                        f"[yellow]{setup.services.number_of_delegated_bins}[/]"
                    ),
                    "",
                )

            console.print("\n", role_table)
            confirm_config = prompt.Confirm.ask(
                f"\nIs the [cyan]{role.value}[/] [yellow]configuration[/] "
                "correct?"
            )
            if confirm_config is False:
                # reconfigure role and keys
                _configure_role(role)

                # if root, reconfigure also the keys
                if role == Roles.ROOT:
                    setup.keys[role].clear()
                    for key in _configure_keys(
                        role.value,
                        setup.number_of_keys[Roles.ROOT],
                    ):
                        setup.keys[role].append(key)
            else:
                break


def _run_ceremony_steps(save: bool) -> Dict[str, Any]:
    console.print(markdown.Markdown(CEREMONY_INTRO), width=100)

    ceremony_detailed = prompt.Confirm.ask(
        "\nDo you want more information about roles and responsibilities?"
    )
    if ceremony_detailed is True:
        with console.pager():
            console.print(
                markdown.Markdown(CEREMONY_INTRO_ROLES_RESPONSIBILITIES),
                width=100,
            )

    start_ceremony = prompt.Confirm.ask("\nDo you want to start the ceremony?")

    if start_ceremony is False:
        raise click.ClickException("Ceremony aborted.")

    # STEP 1: configure the roles settings (keys, threshold, expiration)
    console.print(markdown.Markdown(STEP_1), width=80)
    for role in Roles:
        _configure_role(role)

    start_ceremony = prompt.Confirm.ask(
        "\nReady to start loading the keys? Passwords will be "
        "required for keys"
    )
    if start_ceremony is False:
        raise click.ClickException("Ceremony aborted.")

    # STEP 2: configure the online key (one)
    console.print(markdown.Markdown(STEP_2), width=100)
    for key in _configure_keys("ONLINE", number_of_keys=1):
        setup.online_key.key = key.key
        setup.online_key.key_path = key.key_path

    # STEP 3: load the keys
    console.print(markdown.Markdown(STEP_3), width=100)
    for role in Roles:
        if role == Roles.ROOT:
            for key in _configure_keys(
                role.value, setup.number_of_keys[Roles.ROOT]
            ):
                setup.keys[role].append(key)
        else:
            setup.keys[role].append(setup.online_key)

    # STEP 4: user validation
    console.print(markdown.Markdown(STEP_4), width=100)
    _run_user_validation()

    metadata = initialize_metadata(setup, save)

    json_payload: Dict[str, Any] = dict()
    json_payload["settings"] = setup.to_dict()
    json_payload["metadata"] = {
        key: data.to_dict() for key, data in metadata.items()
    }

    return json_payload


@admin.command()
@click.option(
    "-b",
    "--bootstrap",
    "bootstrap",
    help=(
        "Bootstrap a Repository Service for TUF using the Repository Metadata "
        "after Ceremony"
    ),
    required=False,
    is_flag=True,
)
@click.option(
    "-f",
    "--file",
    "file",
    default="payload.json",
    help=(
        "Generate specific JSON Payload compatible with TUF Repository "
        "Service bootstrap after Ceremony"
    ),
    show_default=True,
    required=False,
)
@click.option(
    "-u",
    "--upload",
    help=(
        "Upload existent payload 'file'. Requires '-b/--bootstrap'. "
        "Optional '-f/--file' to use non default file."
    ),
    required=False,
    is_flag=True,
)
@click.option(
    "-s",
    "--save",
    help=(
        "Save a copy of the metadata locally. This option saves the metadata "
        "files (json) in the 'metadata' folder in the current directory."
    ),
    default=False,
    show_default=True,
    is_flag=True,
)
@click.pass_context
def ceremony(
    context: Any, bootstrap: bool, file: str, upload: bool, save: bool
) -> None:
    """
    Start a new Metadata Ceremony.
    """
    settings = context.obj["settings"]
    # option save: creates the folder
    if save is True:
        try:
            os.makedirs("metadata", exist_ok=True)
        except OSError as err:
            raise click.ClickException(str(err))

    # option upload: it requires -b/--bootstrap
    if upload is True and bootstrap is False:
        raise click.ClickException("Requires '-b/--bootstrap' option.")

    # option bootstrap: checks if the server accepts it beforehand
    if bootstrap:
        bs_status = bootstrap_status(settings)
        if bs_status.get("data", {}).get("bootstrap") is True:
            raise click.ClickException(f"{bs_status.get('message')}")

    # option bootstrap + upload: bootstrap payload is available, skips ceremony
    if bootstrap is True and upload is True:
        bootstrap_payload = _load_bootstrap_payload(file)
        console.print("Starting online bootstrap")
        task_id = _send_bootstrap(settings, bootstrap_payload)
        task_status(task_id, settings, "Bootstrap status: ")
        console.print(f"Bootstrap completed using `{file}`. 🔐 🎉")

    # option ceremony: runs the ceremony, save the payload
    else:
        bootstrap_payload = _run_ceremony_steps(save)
        _save_bootstrap_payload(file, bootstrap_payload)
        console.print(
            f"\nCeremony done. 🔐 🎉. Bootstrap payload ({file}) saved."
        )

        if bootstrap is True:
            task_id = _send_bootstrap(settings, bootstrap_payload)
            task_status(task_id, settings, "Bootstrap status: ")
            console.print("\nCeremony done. 🔐 🎉. Bootstrap completed.")
