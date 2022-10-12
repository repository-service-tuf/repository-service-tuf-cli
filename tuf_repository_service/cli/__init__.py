import importlib
import os
import pkgutil
from pathlib import Path

import rich_click as click  # type: ignore
import tomli

from tuf_repository_service import Dynaconf
from tuf_repository_service.__version__ import version

HOME = str(Path.home())

with open("pyproject.toml", mode="rb") as fp:
    pyproject_config = tomli.load(fp)
prog_name = list(pyproject_config["project"]["scripts"].keys())[0]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".trs.ini"),
    help="TUF Repository Service config file",
    required=False,
)
# adds the --version parameter
@click.version_option(prog_name=prog_name, version=version)
@click.pass_context
def trs(context, config):
    """
    TUF Repository Service Command Line Interface (CLI).
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
