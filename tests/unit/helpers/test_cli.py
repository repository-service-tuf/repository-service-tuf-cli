# SPDX-License-Identifier: MIT

import hashlib
import os
import tempfile
from typing import Iterator

import pytest

from repository_service_tuf.helpers.cli import (
    calculate_blake2b_256,
    create_artifact_add_payload_from_filepath,
    create_artifact_delete_payload_from_filepath,
)


class TestCLIHelpers:
    """Test the CLI helper functions"""

    @pytest.fixture()
    def temp_file(self) -> Iterator[str]:
        """Simple temp file for tests"""

        temp_fd, test_file_path = tempfile.mkstemp(prefix="fake_file_")

        with os.fdopen(temp_fd, "w") as temp_file:
            temp_file.write("Fake data")

        try:
            yield test_file_path

        finally:
            os.remove(test_file_path)

    @pytest.fixture()
    def blake2b_256_hash_temp_file(self, temp_file: str) -> str:
        """blake2b-256 hash of the `temp_file` fixture"""

        hasher = hashlib.blake2b(digest_size=32)

        with open(temp_file, "rb") as f:
            hasher.update(f.read())
            return hasher.hexdigest()

    def test_calculate_blake2b_256(
        self, temp_file: str, blake2b_256_hash_temp_file: str
    ) -> None:
        """Test that the blake2b-256 hash of a file is calculated correctly"""

        assert (
            calculate_blake2b_256(filepath=temp_file)
            == blake2b_256_hash_temp_file
        )

    def test_create_artifact_add_payload_from_filepath(
        self, temp_file: str, blake2b_256_hash_temp_file: str
    ) -> None:
        """
        Test that the artifact payload is created correctly given the
        filepath of the artifact
        """

        path = "/fake/path/"

        expected_artifact_payload = {
            "targets": [
                {
                    "info": {
                        "length": os.path.getsize(temp_file),
                        "hashes": {
                            "blake2b-256": blake2b_256_hash_temp_file,
                        },
                        "custom": None,
                    },
                    "path": f"{path}{temp_file.split('/')[-1]}",
                }
            ],
            "add_task_id_to_custom": False,
            "publish_targets": True,
        }

        assert (
            create_artifact_add_payload_from_filepath(
                filepath=temp_file,
                path=path,
            )
            == expected_artifact_payload
        )

    def test_create_artifact_delete_payload_from_filepath(
        self,
        temp_file: str,
    ) -> None:
        """
        Test that the artifact payload is created correctly given the
        filepath of the artifact
        """

        path = "/fake/path/"

        expected_artifact_payload = {
            "targets": [f"{path}{temp_file.split('/')[-1]}"]
        }

        result = create_artifact_delete_payload_from_filepath(
            filepath=temp_file,
            path=path,
        )
        assert result == expected_artifact_payload

    def test_create_artifact_add_payload_from_filepath_without_path(
        self,
        temp_file: str,
    ) -> None:
        """
        Test that the artifact payload is created correctly given the
        filepath of the artifact
        """

        path = None

        expected_artifact_payload = {
            "targets": [f"{temp_file.split('/')[-1]}"]
        }

        result = create_artifact_delete_payload_from_filepath(
            filepath=temp_file,
            path=path,
        )
        assert result == expected_artifact_payload
