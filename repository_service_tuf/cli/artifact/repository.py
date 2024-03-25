# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT


import base64

from click import Context
from dynaconf.loaders.yaml_loader import write  # type: ignore

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.artifact import artifact


def write_config(settings_path, settings_data, merge=False):
    """
    Writes config data to the rstuf config file. The expected data
    is a dict of type:\n
    {\n
        "CURRENT_REPOSITORY": "<repository_name>",\n
        "REPOSITORIES": {\n
            "<repository_name>": {\n
                "artifact_base_url": "<url>",\n
                "hash_prefix": "<True/False>",\n
                "metadata_url": "<url>",\n
                "trusted_root": "<base64_path_string",\n
            },\n
        },\n
        "SERVER": "<server_url>",\n
    }
    """
    write(settings_path, settings_data, merge)  # pragma: no cover


@artifact.group()
@click.pass_context
def repository(context) -> None:
    """
    Repository management.
    """


@repository.command()
@click.pass_context
@click.argument("repository", required=False)
def show(
    context: Context,
    repository: str,
) -> None:
    """
    List configured repositories.
    """

    rstuf_config = context.obj.get("settings")

    current_repository = rstuf_config.get("CURRENT_REPOSITORY")
    if repository:
        if rstuf_config.get("REPOSITORIES") and rstuf_config[
            "REPOSITORIES"
        ].get(repository):
            if current_repository and current_repository == repository:
                console.print("CURRENT REPOSITORY:")
            try:
                console.print_json(
                    data=dict(
                        {
                            repository: rstuf_config["REPOSITORIES"].get(
                                repository
                            )
                        }
                    )
                )
            except TypeError:
                raise click.ClickException(
                    f"Repository {repository} has incorrect configuration. "
                    "Please verify you're using proper types:\n"
                    "artifact_base_url: <string>\n"
                    "hash_prefix: <bool>\n"
                    "metadata_url: <string>\n"
                    "trusted_root: <base64 string>\n"
                )
        else:
            raise click.ClickException(
                f"Repository {repository} is missing in your configuration"
            )
    else:
        if rstuf_config.get("REPOSITORIES"):
            is_default = ""
            for repo in rstuf_config.get("REPOSITORIES").keys():
                if current_repository and current_repository == repo:
                    style = "b green"
                    is_default = " (default)"
                else:
                    style = "b white"
                    is_default = ""
                console.print(f"{repo}{is_default}", style=style)
        else:
            raise click.ClickException("There are no configured repositories")


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
        write_config(context.obj.get("config"), rstuf_config)
        console.print(f"Current repository changed to {repository}")


@repository.command()
@click.option(
    "-n",
    "--name",
    help="The repository name.",
    type=str,
    required=True,
    default=None,
)
@click.option(
    "-r",
    "--root",
    help="The metadata URL to the initial trusted root or a local file.",
    type=str,
    required=True,
    default=None,
)
@click.option(
    "-m",
    "--metadata-url",
    help="TUF Metadata repository URL.",
    type=str,
    required=True,
    default=None,
)
@click.option(
    "-a",
    "--artifacts-url",
    help="The artifacts base URL to fetch from.",
    type=str,
    required=True,
    default=None,
)
@click.option(
    "-p",
    "--hash-prefix",
    help="Whether to add a hash prefix to artifact names.",
    is_flag=True,
    required=None,
)
@click.pass_context
def add(
    context: Context,
    name: str,
    root: str,
    metadata_url: str,
    artifacts_url: str,
    hash_prefix: bool,
) -> None:
    """
    Add a new repository.
    """

    rstuf_config = context.obj.get("settings").as_dict()

    success_msg: str = f"Successfully added {name} repository to config"
    if rstuf_config.get("REPOSITORIES") and rstuf_config["REPOSITORIES"].get(
        name
    ):
        console.print(f"Repository {name} already configured")
        success_msg = f"Successfully updated repository {name}"

    encoded_root = b""
    if root:
        encoded_root = base64.b64encode(bytes(root, "utf-8"))

    repo_data = {
        "artifact_base_url": artifacts_url,
        "metadata_url": metadata_url,
        "trusted_root": encoded_root.decode("UTF-8"),
        "hash_prefix": hash_prefix,
    }

    if rstuf_config.get("REPOSITORIES"):
        rstuf_config["REPOSITORIES"][name] = repo_data
    else:
        rstuf_config["REPOSITORIES"] = {name: repo_data}

    if context.obj.get("config"):
        write_config(context.obj.get("config"), rstuf_config)
        console.print(success_msg)


@repository.command()
@click.option(
    "-r",
    "--root",
    help="The metadata URL to the initial trusted root or a local file.",
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
    help="The artifacts base URL to fetch from.",
    type=str,
    required=None,
    default=None,
)
@click.option(
    "-p",
    "--hash-prefix",
    help="Whether to add a hash prefix to artifact names.",
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
        raise click.ClickException(
            "There are no configured repositories to update"
        )

    if not rstuf_config["REPOSITORIES"].get(repository):
        raise click.ClickException(
            f"Repository {repository} not available in config. "
            "You can create it instead"
        )

    if root:
        rstuf_config["REPOSITORIES"][repository]["trusted_root"] = (
            base64.b64encode(bytes(root, "utf-8"))
        )
    if metadata_url:
        rstuf_config["REPOSITORIES"][repository]["metadata_url"] = metadata_url
    if artifacts_url:
        rstuf_config["REPOSITORIES"][repository][
            "artifact_base_url"
        ] = artifacts_url
    rstuf_config["REPOSITORIES"][repository]["hash_prefix"] = hash_prefix

    if context.obj.get("config"):
        write_config(context.obj.get("config"), rstuf_config)
        console.print(f"Successfully updated repository {repository}")


@repository.command()
@click.pass_context
@click.argument("repository")
def delete(context: Context, repository: str) -> None:
    """
    Delete a repository.
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
        write_config(context.obj.get("config"), rstuf_config)
        console.print(f"Succesfully deleted repository {repo}")
