# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import importlib
import os
import pkgutil
import re
import sys
from pathlib import Path

import rich_click as click  # type: ignore
from auto_click_auto import enable_click_shell_completion
from auto_click_auto.constants import ShellType
from rich.console import Console
from rich.panel import Panel

from repository_service_tuf import Dynaconf
from repository_service_tuf.__version__ import version

console = Console()
HOME = str(Path.home())

# attempt to find the program name from pyproject.toml or give a default
prog_name = "rstuf"
try:
    with open("pyproject.toml") as file:
        for line in file:
            match = re.search("repository_service_tuf.cli:rstuf", line)

            if match:
                prog_name = line.split("=")[0].strip()
                break

except FileNotFoundError:
    pass


@click.group(  # type: ignore
    context_settings={"help_option_names": ["-h", "--help"]}
)
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".rstuf.ini"),
    help="Repository Service for TUF config file.",
    required=False,
)
@click.option(
    "--auth",
    "auth",
    help="Use of RSTUF built-in authentication.",
    is_flag=True,
    default=False,
    required=False,
)
# adds the --version parameter
@click.version_option(prog_name=prog_name, version=version)
@click.pass_context
def rstuf(context, config, auth):
    """
    Repository Service for TUF Command Line Interface (CLI).
    """
    context.obj = {
        "settings": Dynaconf(settings_files=[config]),
        "config": config,
        "auth": auth,
    }
    settings = context.obj["settings"]
    if auth is True:
        console.print(
            Panel(
                "[white]Using RSTUF built-in authentication (--auth)[/]",
                title="[green]Info[/]",
                title_align="left",
                style="green",
            )
        )
    settings.AUTH = auth


# Register all command groups
groups_required_auth = [
    "repository_service_tuf.cli.admin.token",
    "repository_service_tuf.cli.admin.login",
]
for _, name, _ in pkgutil.walk_packages(  # type: ignore
    __path__, prefix=__name__ + "."
):
    if name in groups_required_auth and "--auth" not in sys.argv:
        continue
    else:
        importlib.import_module(name)

# Enable tab completion for all available supported shells
supported_shell_types = {
    ShellType(shell) for shell in ShellType.get_all_values()
}
enable_click_shell_completion(
    program_name=prog_name, shells=supported_shell_types
)
