# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from repository_service_tuf.__version__ import version
from repository_service_tuf.cli import rstuf


class TestRSTUFCLI:
    def test_tuf_repository_service(self, client):
        test_result = client.invoke(rstuf)
        assert test_result.exit_code == 0

    def test_version_parameter(self, client):
        """Tests the CLI --version parameter existence and output format."""

        result = client.invoke(rstuf, ["--version"])

        assert result.exit_code == 0
        assert result.output == f"rstuf, version {version}\n"
