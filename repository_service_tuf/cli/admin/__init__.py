# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from repository_service_tuf.cli import rstuf


@rstuf.group()  # type: ignore
def admin():
    """Administrative Commands"""
