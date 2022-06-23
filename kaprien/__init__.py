import importlib
import pkgutil

import rich_click as click  # type: ignore


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def kaprien():
    """
    KAPRIEN Command Line Interface (CLI) helps you to manage your KAPRIEN.
    """


# Register all command groups
for _, name, _ in pkgutil.walk_packages(  # type: ignore
    __path__, prefix=__name__ + "."
):
    importlib.import_module(name)
