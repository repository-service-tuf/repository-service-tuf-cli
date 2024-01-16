# SPDX-License-Identifier: MIT

import os
import uuid
from hashlib import sha256
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch
from urllib import request

from repository_service_tuf.cli.artifact import download

example_home_dir: str = "example_home_" + str(uuid.uuid4())[:8]


class TestDownloadArtifacInteraction:
    """Test the artifact download command interaction"""

    def test_dowlnoad_command_without_config_missing_metadata_url(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "file.txt"

        test_result = client.invoke(
            download.download,
            artifact_name,
            obj=test_context,
        )

        assert "Please specify metadata url" in test_result.output
        assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_missing_artifacts_url(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "file.txt"
        metadata_url = "http://localhost:8080"

        test_result = client.invoke(
            download.download,
            [artifact_name, "-m", metadata_url],
            obj=test_context,
        )

        assert "Please specify artifacts url" in test_result.output
        assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_using_tofu(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "file.txt"

        with patch.object(Path, "home") as mock_exists:
            mock_exists.return_value = example_home_dir
            expected_root_path = (
                f"{example_home_dir}/.local/share/rstuf/a76d8c3e"
            )

            metadata_url = "http://localhost:8080"
            artifact_url = "http://localhost:8081"
            with mock.patch("urllib.request.urlretrieve"):
                request.urlretrieve = MagicMock(
                    filename=f"{expected_root_path}/root.json"
                )

                test_result = client.invoke(
                    download.download,
                    [
                        artifact_name,
                        "-m",
                        metadata_url,
                        "-a",
                        artifact_url,
                    ],
                    obj=test_context,
                )

                assert "Trusted local root not found" in test_result.output
                assert (
                    f"Using 'tofu' to Trust-On-First-Use or copy trusted\nroot metadata to {expected_root_path}/root.json"  # noqa
                    in test_result.output
                )
                assert (
                    f"Trust-on-First-Use: Initialized new root in \n{expected_root_path}"  # noqa
                    in test_result.output
                )
                assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_with_trusted_root(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "file.txt"
        metadata_url = "http://localhost:8080"
        artifact_url = "http://localhost:8081"
        trusted_root_path = "tests/files/artifact_download"
        with mock.patch(
            "repository_service_tuf.cli.artifact.download.build_metadata_dir"  # noqa
        ):
            download.build_metadata_dir = MagicMock(
                return_value=trusted_root_path
            )

            test_result = client.invoke(
                download.download,
                [
                    artifact_name,
                    "-m",
                    metadata_url,
                    "-a",
                    artifact_url,
                ],
                obj=test_context,
            )
            expected_root_path = trusted_root_path
            assert (
                f"Using trusted root in {expected_root_path}"
                in test_result.output
            )
            assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_with_artifact_url(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "file.txt"
        metadata_url = "http://localhost:8080"
        artifact_url = "http://localhost:8081"
        trusted_root_path = "tests/files/artifact_download"
        with mock.patch(
            "repository_service_tuf.cli.artifact.download.build_metadata_dir"  # noqa
        ):
            download.build_metadata_dir = MagicMock(
                return_value=trusted_root_path
            )

            with mock.patch(
                "repository_service_tuf.cli.artifact.download.download_artifact"  # noqa
            ):
                download.build_metadata_dir = MagicMock(return_value=True)
                test_result = client.invoke(
                    download.download,
                    [
                        artifact_name,
                        "-m",
                        metadata_url,
                        "-a",
                        artifact_url,
                    ],
                    obj=test_context,
                )
                assert (
                    f"Successfully completed artifact download: {artifact_name}"  # noqa
                    in test_result.output
                )
                assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_with_hash_prefix(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "example_path/file.txt"
        metadata_url = "http://localhost:8080"
        artifact_url = "http://localhost:8081"
        trusted_root_path = "tests/files/artifact_download"
        with mock.patch(
            "repository_service_tuf.cli.artifact.download.build_metadata_dir"  # noqa
        ):
            download.build_metadata_dir = MagicMock(
                return_value=trusted_root_path
            )

            with mock.patch(
                "repository_service_tuf.cli.artifact.download.download_artifact"  # noqa
            ):
                download.build_metadata_dir = MagicMock(return_value=True)
                test_result = client.invoke(
                    download.download,
                    [
                        artifact_name,
                        "-m",
                        metadata_url,
                        "-a",
                        artifact_url,
                        "-p",
                    ],
                    obj=test_context,
                )
                assert (
                    "Successfully completed artifact download"
                    in test_result.output
                )
                assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_with_directory_prefix(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "example_path/file.txt"
        metadata_url = "http://localhost:8080"
        artifact_url = "http://localhost:8081"
        trusted_root_path = "tests/files/artifact_download"
        directory_prefix = os.getcwd() + "/downloads"
        with mock.patch(
            "repository_service_tuf.cli.artifact.download.build_metadata_dir"  # noqa
        ):
            download.build_metadata_dir = MagicMock(
                return_value=trusted_root_path
            )

            with mock.patch(
                "repository_service_tuf.cli.artifact.download.download_artifact"  # noqa
            ):
                download.build_metadata_dir = MagicMock(return_value=True)
                test_result = client.invoke(
                    download.download,
                    [
                        artifact_name,
                        "-m",
                        metadata_url,
                        "-a",
                        artifact_url,
                        "-P",
                        directory_prefix,
                    ],
                    obj=test_context,
                )
                assert (
                    "Successfully completed artifact download"
                    in test_result.output
                )
                assert test_result.exit_code == 0

    def test_dowlnoad_command_without_config_failed_to_download_artifact(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "non-existing"
        metadata_url = "http://localhost:8080"
        artifact_url = "http://localhost:8081"
        trusted_root_path = "tests/files/artifact_download"

        with patch.object(Path, "home") as mock_exists:
            mock_exists.return_value = example_home_dir
            expected_root_path = (
                f"{example_home_dir}/.local/share/rstuf/a76d8c3e"
            )

            with mock.patch("urllib.request.urlretrieve"):
                request.urlretrieve = MagicMock(
                    filename=f"{expected_root_path}/root.json"
                )
                with mock.patch(
                    "repository_service_tuf.cli.artifact.download.build_metadata_dir"  # noqa
                ):
                    download.build_metadata_dir = MagicMock(
                        return_value=trusted_root_path
                    )

                    test_result = client.invoke(
                        download.download,
                        [
                            artifact_name,
                            "-m",
                            metadata_url,
                            "-a",
                            artifact_url,
                        ],
                        obj=test_context,
                    )
                    expected_root_path = trusted_root_path
                    assert (
                        f"Using trusted root in {expected_root_path}"
                        in test_result.output
                    )
                    assert (
                        f"Failed to download artifact {artifact_name}"
                        in test_result.output
                    )
                    assert test_result.exit_code == 0

    def test_dowlnoad_command_with_failing_tofu(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        artifact_name = "file.txt"

        with patch.object(Path, "home") as mock_exists:
            mock_exists.return_value = example_home_dir
            expected_root_path = (
                f"{example_home_dir}/.local/share/rstuf/a76d8c3e"
            )

            metadata_url = "http://localhost:8080"
            artifact_url = "http://localhost:8081"
            with mock.patch(
                "repository_service_tuf.cli.artifact.download.init_tofu"
            ):
                download.init_tofu = MagicMock(return_value=False)

                test_result = client.invoke(
                    download.download,
                    [
                        artifact_name,
                        "-m",
                        metadata_url,
                        "-a",
                        artifact_url,
                    ],
                    obj=test_context,
                )

                assert "Trusted local root not found" in test_result.output
                assert (
                    f"Using 'tofu' to Trust-On-First-Use or copy trusted\nroot metadata to {expected_root_path}/root.json"  # noqa
                    in test_result.output
                )
                assert (
                    f"Trusted local root not found in {metadata_url} - `tofu` was not \nsuccessful\n"  # noqa
                    in test_result.output
                )
                assert test_result.exit_code == 0

    def test_dowlnoad_command_with_config_no_current_repo(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        config = {
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "false",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        artifact_name = "file1.txt"

        test_context["settings"] = config
        with mock.patch("os.path.isfile"):
            os.path.isfile = MagicMock(return_value=True)

            test_result = client.invoke(
                download.download,
                [artifact_name],
                obj=test_context,
            )
            assert "Please specify current repository" in test_result.output

    def test_dowlnoad_command_with_config_no_repos_listed(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {},
            "SERVER": "http://127.0.0.1",
        }
        artifact_name = "file1.txt"

        test_context["settings"] = config
        with mock.patch("os.path.isfile"):
            os.path.isfile = MagicMock(return_value=True)

            test_result = client.invoke(
                download.download,
                [artifact_name],
                obj=test_context,
            )
            assert (
                "No reposotiroes listed in the config file"
                in test_result.output
            )

    def test_dowlnoad_command_with_config_repo_is_missing(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        config = {
            "CURRENT_REPOSITORY": "r1_expected",
            "REPOSITORIES": {
                "r2_other": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "false",
                    "metadata_url": "http://localhost:8080",
                    "trusted_root": "some_root",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        artifact_name = "file1.txt"

        test_context["settings"] = config
        with mock.patch("os.path.isfile"):
            os.path.isfile = MagicMock(return_value=True)

            test_result = client.invoke(
                download.download,
                [artifact_name],
                obj=test_context,
            )
            assert (
                "Repository r1_expected is missing in the configuration file"
                in test_result.output
            )

    def test_dowlnoad_command_with_config_no_trusted_root(
        self, client, test_context, test_setup
    ):
        download.setup = test_setup
        config = {
            "CURRENT_REPOSITORY": "r1",
            "REPOSITORIES": {
                "r1": {
                    "artifact_base_url": "http://localhost:8081",
                    "hash_prefix": "false",
                    "metadata_url": "http://localhost:8080",
                },
            },
            "SERVER": "http://127.0.0.1",
        }
        artifact_name = "file1.txt"

        test_context["settings"] = config
        with mock.patch("os.path.isfile"):
            os.path.isfile = MagicMock(return_value=True)

            test_result = client.invoke(
                download.download,
                [artifact_name],
                obj=test_context,
            )
            assert "Trusted root is not cofigured." in test_result.output
            assert (
                "You should either add it to your config file, or"
                in test_result.output
            )
            assert (
                "use the download commang without a config file"
                in test_result.output
            )


class TestDownloadArtifactOptions:
    """Test the artifact download command heplers"""

    def test_update_artifact_url_with_hash_prefix(self):
        artifact_name = "example_project/file1.tar.gz"
        want = "example_project/f8-ff-file1.tar.gz"
        actual = download.update_artifact_name_with_hash_prefix(artifact_name)
        assert want == actual

    def test_decode_trusted_root(self):
        trusted_root = "ZXhhbXBsZS9ob21lL3BhdGgvLmxvY2FsL3NoYXJlL3JzdHVmL3Jvb3QuanNvbg=="  # noqa
        want = "example/home/path/.local/share/rstuf/root.json"
        actual = download.decode_trusted_root(trusted_root)
        assert want == actual

    def test_build_metadata_dir(self):
        metadata_url = "http://example.org"
        metadata_url_hash = sha256(metadata_url.encode()).hexdigest()[:8]
        want = "example_home/.local/share/rstuf/" + metadata_url_hash
        with patch.object(Path, "home") as mock_exists:
            mock_exists.return_value = "example_home"
            actual = download.build_metadata_dir(metadata_url)
            assert want == actual
