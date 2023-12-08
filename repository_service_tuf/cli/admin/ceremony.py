# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

#
# Ceremony
#
import os
from typing import Any, Dict, Generator, Optional

from rich import box, markdown, prompt, table  # type: ignore

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.constants import SCHEME_DEFAULTS, KeyType
from repository_service_tuf.helpers.api_client import (
    URL,
    bootstrap_status,
    send_payload,
    task_status,
)
from repository_service_tuf.helpers.tuf import (
    BootstrapSetup,
    Roles,
    RSTUFKey,
    ServiceSettings,
    TUFManagement,
    _conform_rsa_key,
    get_key,
    get_supported_schemes_for_key_type,
    load_payload,
    save_payload,
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

Uses one single online key.
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

Note: It requires the public key information (key id/public hash) only.

Tip: "rstuf key info:" retrieves the public information
"""

STEP_3 = """
# STEP 3: Load Root Keys

## Root Keys
The keys must have a password, and the file must be accessible.

Depending on the organization, each key has an owner, and each owner should
insert their password personally.

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

As we said the artifacts will be uniformly distributed over the 8 bins no
matter if they are located in the same folder.
In this example here is how they will be distributed:
- "1.bins-0.json" will be responsible for file:
 https://example.com/downloads/productA/productA-v1.0.tar
- "1.bins-1.json" will be responsible for file:
 https://example.com/downloads/productB/productB-v1.0.tar
- "1.bins-5.json" will be responsible for file:
 https://example.com/downloads/productB/updates/servicepack-1.tar
"""


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
    root_keys={},
    online_key=RSTUFKey(),
)


def _key_already_in_use(key: Dict[str, Any]) -> bool:
    """Check if a key is duplicated, used in a role or the online_key"""
    if key is None:
        return False

    keyid = key["keyid"]
    if keyid == setup.online_key.key.get("keyid"):
        return True

    if setup.root_keys.get(keyid) is not None:
        return True

    return False


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
    role_expiration = 0
    while True:
        role_expiration = prompt.IntPrompt.ask(
            (
                "\nWhat is the [green]metadata expiration[/] for "
                f"the [cyan]{role.value}[/] role?(Days)"
            ),
            default=setup.expiration[role],
            show_default=True,
        )
        if role_expiration < 1:
            console.print(f"Expiration of {role.value} must be at least 1 day")
        else:
            break

    setup.expiration[role] = role_expiration

    if role == Roles.ROOT:
        _configure_role_root()

    if role == Roles.TARGETS:
        _configure_role_target()


def _configure_keys(
    role: str, number_of_keys: int
) -> Generator[RSTUFKey, None, None]:
    role_cyan = click.style(role, fg="cyan")
    key_count = 1
    while key_count <= number_of_keys:
        console.print(
            f"\n🔑 Key {key_count}/{number_of_keys} [cyan]{role}[/]\n"
        )

        if role == Roles.ROOT.value and key_count == 1:
            signing_key = "private"

        elif role == "ONLINE":
            signing_key = "public"
        else:
            signing_key = prompt.Prompt.ask(
                "[cyan]Private[/] or [cyan]Public[/] key"
                "\n- [cyan]private key[/] requires the file path and password"
                "\n- [cyan]public info[/] requires the a key id and key hash"
                "\n  tip: `rstuf key info` retrieves the public information"
                "\nSelect to use [cyan]private key[/] or [cyan]public "
                "info[/]?",
                choices=["private", "public"],
                default="public",
            )

        key_type = prompt.Prompt.ask(
            f"Choose {role_cyan}`s key type",
            choices=KeyType.get_all_members(),
            default=KeyType.KEY_TYPE_ED25519.value,
        )
        if signing_key == "private":
            role_key: RSTUFKey = get_key(role, key_type, ask_name=True)
            if role_key.error:
                console.print(role_key.error)
                continue

            console.print(
                ":white_check_mark: Key "
                f"{key_count}/{number_of_keys} [green]Verified[/]"
            )

        else:
            allowed_schemes = get_supported_schemes_for_key_type(key_type)
            # No point of asking the user for choice if there is only 1 scheme.
            if len(allowed_schemes) == 1:
                scheme = allowed_schemes[0]
            else:
                scheme = prompt.Prompt.ask(
                    f"Choose {role_cyan}`s [green]public key scheme[/]",
                    choices=allowed_schemes,
                    default=SCHEME_DEFAULTS[key_type],
                )

            while True:
                keyid = prompt.Prompt.ask(
                    f"Enter {role_cyan}`s [green]key id[/]"
                )
                if keyid.strip() != "":
                    break

            while True:
                public = prompt.Prompt.ask(
                    f"Enter {role_cyan}`s [green]public key hash[/]"
                )
                if public.strip() != "":
                    if key_type == KeyType.KEY_TYPE_RSA.value:
                        public = _conform_rsa_key(public)

                    break

            name = prompt.Prompt.ask(
                f"[Optional] Give a [green]name/tag[/] to the {role_cyan} key",
                default=keyid[:7],
                show_default=False,
            )

            role_key = RSTUFKey(
                key={
                    "keytype": key_type,
                    "scheme": scheme,
                    "keyid": keyid,
                    "keyid_hash_algorithms": ["sha256", "sha512"],
                    "keyval": {
                        "public": public,
                    },
                },
                key_path="N/A (public key only)",
                name=name,
            )

        if role_key.key.get("keyid") is None:
            console.print(":cross_mark: [red]Failed[/]: Key `keyid` is None.")
            continue

        if _key_already_in_use(role_key.key) is True:
            console.print(":cross_mark: [red]Failed[/]: Key is duplicated.")
            continue

        yield role_key

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
                "Path", justify="right", style="cyan", no_wrap=True
            )
        keys_table.add_column("Storage", justify="center")
        keys_table.add_column("Verified", justify="center")
        keys_table.add_column("Name/Tag", justify="center")
        keys_table.add_column("Id", justify="center")
        keys_table.add_column("Key Type", justify="center")
        keys_table.add_column("Key Scheme", justify="center")

        return keys_table

    def _add_row_keys_table(table: table.Table, key: RSTUFKey, storage: str):
        table.add_row(
            f"[yellow]{key.key_path}[/]",
            f"[green]{storage}[/]",
            ":white_heavy_check_mark:",
            f"[yellow]{key.name}",
            f"[yellow]{key.key.get('keyid')}[/]",
            f"[yellow]{key.key.get('keytype')}[/]",
            f"[yellow]{key.key.get('scheme')}[/]",
        )

    # Validations
    #
    # Online key validation
    while True:
        online_key_table = _init_summary_table("ONLINE KEY SUMMARY")
        keys_table = _init_keys_table()
        _add_row_keys_table(keys_table, setup.online_key, "Online")

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
                for key in setup.root_keys.values():
                    _add_row_keys_table(keys_table, key, "Offline")

                role_table.add_row(
                    (
                        f"Role: [cyan]{role.value}[/]"
                        f"\nNumber of Keys: [yellow]{len(setup.root_keys)}[/]"
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
                    _add_row_keys_table(keys_table, setup.online_key, "Online")

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
                    setup.root_keys.clear()
                    for key in _configure_keys(
                        role.value,
                        setup.number_of_keys[Roles.ROOT],
                    ):
                        setup.root_keys[key.key["keyid"]] = key
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

    # STEP 2: configure the online key (one)
    console.print(markdown.Markdown(STEP_2), width=100)
    for key in _configure_keys("ONLINE", number_of_keys=1):
        setup.online_key = key

    start_ceremony = prompt.Confirm.ask(
        "\nReady to start loading the root keys?"
    )
    if start_ceremony is False:
        raise click.ClickException("Ceremony aborted.")

    # STEP 3: load the root keys
    console.print(markdown.Markdown(STEP_3), width=100)
    root = Roles.ROOT.value
    for key in _configure_keys(root, setup.number_of_keys[Roles.ROOT]):
        setup.root_keys[key.key["keyid"]] = key

    # STEP 4: user validation
    console.print(markdown.Markdown(STEP_4), width=100)
    _run_user_validation()

    tuf_management = TUFManagement(setup, save)
    metadata = tuf_management.initialize_metadata()

    # Inform user for pending signatures
    pending_signatures: int = setup.threshold[Roles.ROOT] - len(
        metadata[Roles.ROOT.value].signatures
    )
    if pending_signatures > 0:
        console.print(
            "Root is not trustworthy yet,"
            f" {pending_signatures} pending signature(s) left.",
        )

    json_payload: Dict[str, Any] = dict()
    json_payload["settings"] = setup.to_dict()
    json_payload["metadata"] = {
        key: data.to_dict() for key, data in metadata.items()
    }

    return json_payload


@admin.command()  # type: ignore
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
        "Optional '-f/--file' to use non default file name."
    ),
    required=False,
    is_flag=True,
)
@click.option(
    "--api-server",
    help="RSTUF API Server address. ",
    required=False,
)
@click.option(
    "-s",
    "--save",
    help=(
        "Save a copy of the metadata locally. This option saves the JSON "
        "metadata files in the 'metadata' folder in the current directory."
    ),
    default=False,
    show_default=True,
    is_flag=True,
)
@click.pass_context
def ceremony(
    context: Any,
    bootstrap: bool,
    file: str,
    upload: bool,
    save: bool,
    api_server: str,
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
        if api_server:
            settings.SERVER = api_server

        if settings.get("SERVER") is None:
            raise click.ClickException(
                "Requires '--api-server' "
                "Example: --api-server https://api.rstuf.example.com"
            )

        bs_status = bootstrap_status(settings)
        if bs_status.get("data", {}).get("bootstrap") is True:
            raise click.ClickException(f"{bs_status.get('message')}")

    # option bootstrap + upload: bootstrap payload is available, skips ceremony
    if bootstrap is True and upload is True:
        bootstrap_payload = load_payload(file)
        console.print("Starting online bootstrap")
        task_id = send_payload(
            settings=settings,
            url=URL.BOOTSTRAP.value,
            payload=bootstrap_payload,
            expected_msg="Bootstrap accepted.",
            command_name="Bootstrap",
        )
        task_status(task_id, settings, "Bootstrap status: ")
        console.print(f"Bootstrap completed using `{file}`. 🔐 🎉")

    # option ceremony: runs the ceremony, save the payload
    else:
        bootstrap_payload = _run_ceremony_steps(save)
        save_payload(file, bootstrap_payload)
        console.print(
            f"\nCeremony done. 🔐 🎉. Bootstrap payload ({file}) saved."
        )

        if bootstrap is True:
            task_id = send_payload(
                settings=settings,
                url=URL.BOOTSTRAP.value,
                payload=bootstrap_payload,
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )
            task_status(task_id, settings, "Bootstrap status: ")
            console.print("\nCeremony done. 🔐 🎉. Bootstrap completed.")
