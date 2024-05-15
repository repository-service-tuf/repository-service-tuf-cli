# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from repository_service_tuf.cli import click, rstuf


@rstuf.group()  # type: ignore
def admin_legacy():
    """Administrative (Legacy) Commands"""
    DEPRECATION_WARNING = """
    ATTENTION:

    This command is deprecated and will be removed in a future release.

    This command uses the legacy keys format which are not compatible with
    future versions of the RSTUF.

    Do not use this command unless you are testing with the legacy RSTUF.
    Consider redeploying RSTUF using the new admin commands.

    """
    click.echo(click.style(DEPRECATION_WARNING, bold=True, fg="red"))
