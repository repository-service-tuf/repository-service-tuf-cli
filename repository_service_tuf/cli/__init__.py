# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import importlib
import os
import pkgutil
import re
from pathlib import Path

import rich_click as click  # type: ignore

from repository_service_tuf import Dynaconf
from repository_service_tuf.__version__ import version

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


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".rstuf.ini"),
    help="Repository Service for TUF config file",
    required=False,
)
# adds the --version parameter
@click.version_option(prog_name=prog_name, version=version)
@click.pass_context
def rstuf(context, config):
    """
    Repository Service for TUF Command Line Interface (CLI).
    """
    context.obj = {
        "settings": Dynaconf(settings_files=[config]),
        "config": config,
    }


# Register all command groups
for _, name, _ in pkgutil.walk_packages(  # type: ignore
    __path__, prefix=__name__ + "."
):
    importlib.import_module(name)
