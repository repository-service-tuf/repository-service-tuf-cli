# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT


"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

"""

from repository_service_tuf.cli import click, rstuf


@rstuf.group()  # type: ignore
def admin():
    """Administrative Commands"""


@admin.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """
