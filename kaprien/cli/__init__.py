import importlib
import os
import pkgutil
from pathlib import Path

import rich_click as click  # type: ignore

from kaprien import Dynaconf

HOME = str(Path.home())


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".kaprien.ini"),
    help="Kaprien config file",
    required=False,
)
@click.pass_context
def kaprien(context, config):
    """
    KAPRIEN Command Line Interface (CLI) helps you to manage your KAPRIEN.
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
