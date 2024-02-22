# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import importlib
import os
import pkgutil
import re
from pathlib import Path
from typing import Optional

import rich_click as click  # type: ignore
from auto_click_auto import enable_click_shell_completion_option
from auto_click_auto.constants import ShellType
from click import Context
from rich.console import Console

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

except FileNotFoundError:  # pragma: no cover the tests will fail in general
    pass

# Enable tab completion for all available supported shells
supported_shell_types = {
    ShellType(shell) for shell in ShellType.get_all_values()
}


@click.group(  # type: ignore
    context_settings={"help_option_names": ["-h", "--help"]}
)
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".rstuf.yml"),
    help="Repository Service for TUF config file.",
    show_default=True,
    required=False,
)
# adds the --version parameter
@click.version_option(prog_name=prog_name, version=version)
@enable_click_shell_completion_option(
    program_name=prog_name, shells=supported_shell_types
)
@click.pass_context
def rstuf(
    context: Context,
    config: Optional[str],
):
    """Repository Service for TUF Command Line Interface (CLI)."""
    context.obj = (
        {  # pragma: no cover -- it is just the context without logic.
            "settings": Dynaconf(settings_files=[config]),
            "config": config,
        }
    )


# Register all command groups

for _, name, _ in pkgutil.walk_packages(  # type: ignore
    __path__, prefix=__name__ + "."
):
    importlib.import_module(name)
