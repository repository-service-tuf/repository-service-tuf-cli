# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT


import base64

from click import Context
from dynaconf.loaders.yaml_loader import write  # type: ignore

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.artifact import artifact


def write_config(settings_path, settings_data, merge=True):
    write(settings_path, settings_data, merge)  # pragma: no cover


@artifact.group()
@click.pass_context
def repository(context) -> None:
    """
    Repository management.
    """


@repository.command()
@click.option(
    "-a",
    "--all",
    help="Show all the configured repositories.",
    is_flag=True,
    required=None,
)
@click.pass_context
@click.argument("repository", required=False)
def show(
    context: Context,
    all: bool,
    repository: str,
) -> None:
    """
    List configured repositories.
    """

    rstuf_config = context.obj.get("settings")

    if all:
        if rstuf_config.get("REPOSITORIES"):
            for repo in rstuf_config.get("REPOSITORIES"):
                console.print(repo)
        else:
            raise click.ClickException("There are no configured repositories")

    if repository:
        if rstuf_config.get("REPOSITORIES") and rstuf_config[
            "REPOSITORIES"
        ].get(repository):
            console.print(rstuf_config["REPOSITORIES"].get(repository))
        else:
            raise click.ClickException(
                f"Repository {repository} is missing in your configuration"
            )


@repository.command()
@click.pass_context
@click.argument("repository")
def set(context: Context, repository: str) -> None:
    """
    Switch current repository.
    """

    rstuf_config = context.obj.get("settings").as_dict()

    rstuf_config["CURRENT_REPOSITORY"] = repository
    if context.obj.get("config"):
        write_config(context.obj.get("config"), rstuf_config, False)
        console.print(f"Current repository changed to {repository}")


@repository.command()
@click.option(
    "-r",
    "--root",
    help="A metadata URL to the initial trusted root or a local file.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-m",
    "--metadata-url",
    help="TUF Metadata repository URL.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-a",
    "--artifacts-url",
    help="An artifacts base URL to fetch from.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-p",
    "--hash-prefix",
    help="A hash prefix.",
    is_flag=True,
    required=None,
)
@click.pass_context
@click.argument("repository")
def add(
    context: Context,
    root: str,
    metadata_url: str,
    artifacts_url: str,
    hash_prefix: bool,
    repository: str,
) -> None:
    """
    Add a new repository.
    """

    rstuf_config = context.obj.get("settings").as_dict()

    success_msg: str = f"Successfully added {repository} repository to config"
    if rstuf_config.get("REPOSITORIES") and rstuf_config["REPOSITORIES"].get(
        repository
    ):
        console.print(f"Repository {repository} already configured")
        success_msg = f"Successfully updated repository {repository}"

    encoded_root = b""
    if root:
        encoded_root = base64.b64encode(bytes(root, "utf-8"))

    repo_data = {
        "artifact_base_url": artifacts_url,
        "metadata_url": metadata_url,
        "trusted_root": encoded_root,
        "hash_prefix": hash_prefix,
    }

    if rstuf_config.get("REPOSITORIES"):
        rstuf_config["REPOSITORIES"][repository] = repo_data
    else:
        rstuf_config["REPOSITORIES"] = {repository: repo_data}

    if context.obj.get("config"):
        write_config(context.obj.get("config"), rstuf_config, False)
        console.print(success_msg)


@repository.command()
@click.option(
    "-r",
    "--root",
    help="A metadata URL to the initial trusted root or a local file.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-m",
    "--metadata-url",
    help="TUF Metadata repository URL.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-a",
    "--artifacts-url",
    help="An artifacts base URL to fetch from.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-p",
    "--hash-prefix",
    help="A hash prefix.",
    is_flag=True,
    required=None,
)
@click.pass_context
@click.argument("repository")
def update(
    context: Context,
    root: str,
    metadata_url: str,
    artifacts_url: str,
    hash_prefix: bool,
    repository: str,
) -> None:
    """
    Update repository.
    """

    rstuf_config = context.obj.get("settings").as_dict()

    if not rstuf_config.get("REPOSITORIES"):
        console.print("There are no configured repositories to update")
        return

    if not rstuf_config["REPOSITORIES"].get(repository):
        raise click.ClickException(
            f"Repository {repository} not available in config. "
            "You can create it instead"
        )

    if root:
        rstuf_config["REPOSITORIES"][repository][  # pragma: no cover
            "trusted_root"
        ] = base64.b64encode(bytes(root, "utf-8"))
    if metadata_url:
        rstuf_config["REPOSITORIES"][repository]["metadata_url"] = metadata_url
    if artifacts_url:
        rstuf_config["REPOSITORIES"][repository][  # pragma: no cover
            "artifacts_url"
        ] = artifacts_url
    rstuf_config["REPOSITORIES"][repository]["hash_prefix"] = hash_prefix

    if context.obj.get("config"):
        write_config(context.obj.get("config"), rstuf_config, False)
        console.print(f"Successfully updated repository {repository}")


@repository.command()
@click.pass_context
@click.argument("repository")
def delete(context: Context, repository: str) -> None:
    """
    Delete repository.
    """

    rstuf_config = context.obj.get("settings").as_dict()

    if not rstuf_config.get("REPOSITORIES"):
        raise click.ClickException(
            "There are no configured repositories. Nothing to delete"
        )

    if not rstuf_config["REPOSITORIES"].get(repository):
        raise click.ClickException(
            f"Repository {repository} not available. Nothing to delete"
        )

    repo = rstuf_config["REPOSITORIES"].pop(repository)

    if context.obj.get("config"):
        write_config(context.obj.get("config"), rstuf_config, False)
        console.print(f"Succesfully deleted repository {repo}")
