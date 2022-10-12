import importlib
import os
import pkgutil
from pathlib import Path

import rich_click as click  # type: ignore

from repository_service_tuf import Dynaconf

HOME = str(Path.home())


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-c",
    "--config",
    "config",
    default=os.path.join(HOME, ".rstuf.ini"),
    help="Repository Service for TUF config file",
    required=False,
)
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
