# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import os

from rich import prompt
from rich.console import Console  # type: ignore
from securesystemslib.interface import (  # type: ignore
    _generate_and_write_ecdsa_keypair,
    _generate_and_write_ed25519_keypair,
    _generate_and_write_rsa_keypair,
    _get_key_file_encryption_password,
    get_password,
)

from repository_service_tuf.cli import click
from repository_service_tuf.cli.key import key
from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers.tuf import load_key, print_key_table

console = Console()


def _verify_password(filename: str) -> str:
    """
    Prompt user for password, verify and return it using `securesystemslib`
    conventions for password management
    """

    while True:
        password: str = get_password(
            f"Enter password to encrypt private key file '{str(filename)}': ",
            confirm=True,
        )

        # checks that the password is a string and 1 or more characters long
        try:
            return _get_key_file_encryption_password(password, False, filename)
        except ValueError as err:
            click.echo(err)


@key.command()
def generate() -> None:
    """Generate cryptographic keys using the `securesystemslib` library"""

    key_type: str = prompt.Prompt.ask(
        "\nChoose [green]key type[/]",
        choices=KeyType.get_all_members(),
        default=KeyType.KEY_TYPE_ED25519.value,
    )
    filename: str = prompt.Prompt.ask(
        "Enter the key's [green]filename[/]:",
        default=f"id_{key_type}",
    )
    if os.path.isfile(filename) is True:
        overwrite = prompt.Confirm.ask(
            f"Do you want to [red]overwrite[/] the existing '{filename}' file?"
        )
        if overwrite is False:
            raise click.ClickException("Key creation aborted.")

    password = _verify_password(filename)

    if key_type == KeyType.KEY_TYPE_ED25519.value:
        _generate_and_write_ed25519_keypair(
            password=password, filepath=filename
        )
    elif key_type == KeyType.KEY_TYPE_ECDSA.value:
        _generate_and_write_ecdsa_keypair(password=password, filepath=filename)
    elif key_type == KeyType.KEY_TYPE_RSA.value:
        _generate_and_write_rsa_keypair(password=password, filepath=filename)
    else:  # pragma: no cover
        # Current click configuration will never trigger this case, adding
        # this as a fail-safe if we add new key-types
        raise ValueError(f"Key type `{key_type}` is not supported!")

    rstuf_key = load_key(filename, key_type, password, "")
    print_key_table(rstuf_key)
