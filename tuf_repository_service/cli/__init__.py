import importlib
import os
import pkgutil
from pathlib import Path

import rich_click as click  # type: ignore

from tuf_repository_service import Dynaconf

HOME = str(Path.home())


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".trs.ini"),
    help="TUF Repository Service config file",
    required=False,
)
@click.version_option()
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
