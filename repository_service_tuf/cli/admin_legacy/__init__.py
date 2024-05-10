# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from repository_service_tuf.cli import rstuf


@rstuf.group()  # type: ignore
def admin_legacy():
    """Administrative (Legacy) Commands"""
