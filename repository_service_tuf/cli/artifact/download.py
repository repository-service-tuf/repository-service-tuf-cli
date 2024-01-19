# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT


import base64
import os
from hashlib import sha256
from pathlib import Path
from typing import Optional
from urllib import request
from urllib.parse import urlparse

from click import Context
from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.ngclient import Updater, UpdaterConfig

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.artifact import artifact


def decode_trusted_root(root) -> str:
    root_encoded = bytes(root, "utf-8")
    return base64.b64decode(root_encoded).decode("utf-8")


def build_metadata_dir(metadata_url: str) -> str:
    """build a unique and reproducible directory name for the repository url"""
    name = sha256(metadata_url.encode()).hexdigest()[:8]
    return f"{Path.home()}/.local/share/rstuf/{name}"


def init_tofu(metadata_url: str, root_url: Optional[str]) -> bool:
    """Initialize local trusted metadata (Trust-On-First-Use) and create a
    directory for downloads"""
    metadata_dir = build_metadata_dir(metadata_url)

    os.makedirs(metadata_dir, exist_ok=True)

    if not root_url:
        root_url = f"{metadata_url}/1.root.json"
    try:
        parsed_root_url = urlparse(root_url)
        if parsed_root_url.scheme and parsed_root_url.netloc:
            request.urlretrieve(root_url, f"{metadata_dir}/root.json")  # nosec
        else:
            console.print(  # pragma: no cover
                f"Failed to parse {root_url}: ",
                f"{parsed_root_url.scheme}, {parsed_root_url.netloc}",
            )
    except OSError:  # pragma: no cover
        console.print(f"Failed to download initial root from {root_url}")
        return False  # pragma: no cover

    console.print(
        f"Trust-on-First-Use: Initialized new root in {metadata_dir}"
    )
    return True


def perform_tuf_ngclient_download_artifact(
    metadata_url: str,
    metadata_dir: str,
    artifacts_url: str,
    artifact_name: str,
    download_dir: str,
    config: UpdaterConfig,
) -> bool:
    try:
        updater = Updater(
            metadata_dir=metadata_dir,
            metadata_base_url=metadata_url,
            target_base_url=artifacts_url,
            target_dir=download_dir,
            config=config,
        )
        updater.refresh()

        # Annotating, as it's an external method we don't want to test
        info = updater.get_targetinfo(artifact_name)  # pragma: no cover

        if info is None:  # pragma: no cover
            console.print(f"Artifact {artifact_name} not found")
            return False

        path = updater.find_cached_target(info)  # pragma: no cover
        if path:  # pragma: no cover
            console.print(f"Artifact is available in {path}")
            return True

        path = updater.download_target(info)  # pragma: no cover
        console.print(  # pragma: no cover
            f"Artifact downloaded and available in {path}"
        )

    except (OSError, RepositoryError, DownloadError) as e:
        console.print(f"Failed to download artifact {artifact_name}: {e}")
        return False

    return True


def _download_artifact(
    metadata_url: Optional[str],
    artifacts_url: Optional[str],
    hash_prefix: Optional[bool],
    directory_prefix: Optional[str],
    artifact_name: str,
    root: Optional[str],
) -> bool:
    if metadata_url is None:
        console.print("Please specify metadata url")
        return False
    metadata_dir = build_metadata_dir(metadata_url)

    if artifacts_url is None:
        console.print("Please specify artifacts url")
        return False

    if not os.path.isfile(f"{metadata_dir}/root.json"):
        console.print(
            "Trusted local root not found. Using 'tofu' to "
            "Trust-On-First-Use or copy trusted root metadata to "
            f"{metadata_dir}/root.json"
        )
        ok = init_tofu(metadata_url, root)
        if not ok:
            console.print(
                f"Trusted local root not found in {metadata_url} - "
                "`tofu` was not successful"
            )
            return False

    print(f"Using trusted root in {metadata_dir}")

    if directory_prefix:
        # Annotating as it's covered, but codecov doesn't
        # recognize that properly
        download_dir = directory_prefix  # pragma: no cover
    else:
        download_dir = os.getcwd() + "/downloads"

    if not os.path.isdir(download_dir):
        os.mkdir(download_dir)

    config = UpdaterConfig()
    if not hash_prefix:
        config.prefix_targets_with_hash = False

    res = perform_tuf_ngclient_download_artifact(
        metadata_url,
        metadata_dir,
        artifacts_url,
        artifact_name,
        download_dir,
        config,
    )

    return res


@artifact.command()
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
    help="A flag to prefix an artifact with a hash.",
    is_flag=True,
    required=None,
)
@click.option(
    "-P",
    "--directory-prefix",
    help="A prefix for the download dir.",
    type=str,
    required=None,
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
                console.print(
                    "Trusted root is not cofigured. "
                    "You should either add it to your config file, "
                    "or use the download commang without a config file"
                )
                return
            root = decode_trusted_root(root)  # pragma: no cover
            console.print(f"Decoded trusted root {root}")

    ok = _download_artifact(
        metadata_url,
        artifacts_url,
        hash_prefix,
        directory_prefix,
        artifact_name,
        root,
    )

    if ok:
        console.print(
            f"Successfully completed artifact download: {artifact_name}"
        )
