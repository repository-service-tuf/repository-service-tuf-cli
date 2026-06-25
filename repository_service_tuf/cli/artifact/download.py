# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT


import base64
import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Optional
from urllib import error, request
from urllib.parse import urlparse

from click import Context
from tuf.api.exceptions import DownloadError, RepositoryError, UnsignedMetadataError
from tuf.api.metadata import Metadata, Root
from tuf.ngclient import Updater, UpdaterConfig

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.artifact import artifact


def _decode_trusted_root(root) -> str:
    root_encoded = bytes(root, "utf-8")
    return base64.b64decode(root_encoded).decode("utf-8")


def _check_root(root: bytes) -> None:
    try:
        root_json = json.loads(root.decode("utf-8"))
        root_md: Metadata[Root] = Metadata.from_dict(root_json)
        root_md.verify_delegate(Root.type, root_md)
    except (UnsignedMetadataError, ValueError, json.JSONDecodeError) as e:
        raise click.ClickException(
            f"Invalid trusted root metadata: {e}"
        ) from e


def _load_root_from_file(root: str) -> bytes:
    with open(root, "rb") as f:
        root_data = f.read()

    _check_root(root_data)
    return root_data


def _load_root_from_url(root: str) -> bytes:
    parsed_root = urlparse(root)
    if not (parsed_root.scheme and parsed_root.netloc):
        raise click.ClickException(
            "Please provide a valid trusted root URL with a scheme and host."
        )
    try:
        with request.urlopen(root) as response:  # nosec
            root_data = response.read()
    except error.HTTPError as e:
        raise click.ClickException(
            f"Failed to download trusted root from {root}: {e.code} {e.reason}"
        ) from e
    except error.URLError as e:
        raise click.ClickException(
            f"Failed to download trusted root from {root}: {e.reason}"
        ) from e

    _check_root(root_data)
    return root_data


def _load_trusted_root(root: str) -> bytes:
    if os.path.isfile(root):
        return _load_root_from_file(root)
    parsed_root = urlparse(root)
    if parsed_root.scheme and parsed_root.netloc:
        return _load_root_from_url(root)
    root_data = root.encode("utf-8")   # config path: already JSON text after decode
    _check_root(root_data)
    return root_data


def _build_metadata_dir(metadata_url: str) -> str:
    """build a unique and reproducible directory name for the repository url"""
    name = sha256(metadata_url.encode()).hexdigest()[:8]
    return f"{Path.home()}/.local/share/rstuf/{name}"


def _init_trusted_root(metadata_url: str, root: bytes | str) -> None:
    """Initialize trusted metadata and create a directory for downloads"""
    metadata_dir = _build_metadata_dir(metadata_url)

    os.makedirs(metadata_dir, exist_ok=True)

    with open(f"{metadata_dir}/root.json", "wb") as f:
        if isinstance(root, str):
            root = root.encode("utf-8")
        f.write(root)

    console.print(f"Initialized new root in {metadata_dir}")


def _init_tofu(metadata_url: str) -> None:
    """Initialize local trusted metadata (Trust-On-First-Use) and create a
    directory for downloads"""
    metadata_dir = _build_metadata_dir(metadata_url)

    os.makedirs(metadata_dir, exist_ok=True)

    root = f"{metadata_url}/1.root.json"
    try:
        parsed_root = urlparse(root)
        if parsed_root.scheme and parsed_root.netloc:
            request.urlretrieve(root, f"{metadata_dir}/root.json")  # nosec
        else:
            console.print(  # pragma: no cover
                f"Failed to parse {root}: ",
                f"{parsed_root.scheme}, {parsed_root.netloc}",
            )
    except (OSError, ConnectionError) as e:  # pragma: no cover
        raise click.FileError(
            f"Failed to download initial root from {root}. ",
            f"Trusted local root not found in {metadata_url} - "
            "`tofu` was not successful",
        ) from e

    console.print(
        f"Trust-on-First-Use: Initialized new root in {metadata_dir}"
    )


def _perform_tuf_ngclient_download_artifact(
    metadata_url: str,
    metadata_dir: str,
    artifacts_url: str,
    artifact_name: str,
    download_dir: str,
    config: UpdaterConfig,
    bootstrap: Optional[bytes],
) -> None:
    try:
        updater = Updater(
            metadata_dir=metadata_dir,
            metadata_base_url=metadata_url,
            target_base_url=artifacts_url,
            target_dir=download_dir,
            config=config,
            bootstrap=bootstrap,
        )
        updater.refresh()

        # Annotating, as it's an external method we don't want to test

        info = updater.get_targetinfo(artifact_name)  # pragma: no cover

        if info is None:  # pragma: no cover
            raise click.ClickException(
                f"Artifact {artifact_name} not trusted by TUF repository"
            )

        path = updater.find_cached_target(info)  # pragma: no cover
        if path:  # pragma: no cover
            console.print(f"Artifact is available in {path}")

        path = updater.download_target(info)  # pragma: no cover
        console.print(  # pragma: no cover
            f"Artifact downloaded and available in {path}"
        )

    except (OSError, RepositoryError, DownloadError) as e:
        raise click.FileError(
            f"Failed to download artifact {artifact_name}: {e}"
        )


def _download_artifact(
    metadata_url: Optional[str],
    artifacts_url: Optional[str],
    hash_prefix: Optional[bool],
    directory_prefix: Optional[str],
    artifact_name: str,
    root: Optional[str],
) -> None:
    if metadata_url is None:
        raise click.ClickException("Please specify metadata url")

    metadata_dir = _build_metadata_dir(metadata_url)

    if artifacts_url is None:
        raise click.ClickException("Please specify artifacts url")

    bootstrap = None
    if root is None:
        _init_tofu(metadata_url)
    else:
        root_data = _load_trusted_root(root)
        _init_trusted_root(metadata_url, root_data)
        bootstrap = root_data

    console.print(f"Using trusted root in {metadata_dir}")

    if directory_prefix:
        # Annotating as it's covered, but codecov doesn't
        # recognize that properly
        download_dir = directory_prefix  # pragma: no cover
    else:
        download_dir = os.getcwd() + "/downloads"

    os.makedirs(download_dir, exist_ok=True)

    config = UpdaterConfig()
    if not hash_prefix:
        config.prefix_targets_with_hash = False

    _perform_tuf_ngclient_download_artifact(
        metadata_url,
        metadata_dir,
        artifacts_url,
        artifact_name,
        download_dir,
        config,
        bootstrap,
    )


@artifact.command()
@click.option(
    "-r",
    "--root",
    help=(
        "A metadata URL to the initial trusted root or a local file. If not"
        "given, it will use Trust-On-First-Use."
    ),
    type=str,
    default=None,
)
@click.option(
    "-m",
    "--metadata-url",
    help="TUF Metadata repository URL.",
    type=str,
    default=None,
)
@click.option(
    "-a",
    "--artifacts-url",
    help="An artifacts base URL to fetch from.",
    type=str,
    default=None,
)
@click.option(
    "-p",
    "--hash-prefix",
    help="A flag to prefix an artifact with a hash.",
    is_flag=True,
)
@click.option(
    "-P",
    "--directory-prefix",
    help="A prefix for the download dir.",
    type=str,
    default=None,
)
@click.argument("artifact_name")
@click.pass_context
def download(
    context: Context,
    root: Optional[str],
    metadata_url: Optional[str],
    artifacts_url: Optional[str],
    hash_prefix: Optional[bool],
    directory_prefix: Optional[str],
    artifact_name: str,
) -> None:
    """
    Downloads artifacts to the TUF metadata.
    """

    rstuf_config = context.obj.get("settings")

    if context.obj.get("config") and os.path.isfile(context.obj.get("config")):
        repository = rstuf_config.get("CURRENT_REPOSITORY")
        # Overwriting the config if a flag is passed
        # or using it as default instead
        if not repository:
            raise click.ClickException("Please specify current repository")
        if not rstuf_config.get("REPOSITORIES"):
            raise click.ClickException(
                "No reposotiroes listed in the config file"
            )
        if not rstuf_config["REPOSITORIES"].get(repository):
            raise click.ClickException(
                f"Repository {repository} is missing in the "
                "configuration file"
            )
        if not artifacts_url:
            artifacts_url = rstuf_config["REPOSITORIES"][repository].get(
                "artifact_base_url"
            )
        if not metadata_url:
            metadata_url = rstuf_config["REPOSITORIES"][repository].get(
                "metadata_url"
            )
        if not hash_prefix:
            hash_prefix = rstuf_config["REPOSITORIES"][repository].get(
                "hash_prefix", False
            )
        if not directory_prefix:
            directory_prefix = rstuf_config["REPOSITORIES"][repository].get(
                "download_dir"
            )
        if not root:
            root = rstuf_config["REPOSITORIES"][repository].get("trusted_root")
            if not root:
                raise click.ClickException(
                    "Trusted root is not cofigured. "
                    "You should either add it to your config file, "
                    "or use the download commang without a config file"
                )
            root = _decode_trusted_root(root)  # pragma: no cover

    _download_artifact(
        metadata_url,
        artifacts_url,
        hash_prefix,
        directory_prefix,
        artifact_name,
        root,
    )

    console.print(f"Successfully completed artifact download: {artifact_name}")
