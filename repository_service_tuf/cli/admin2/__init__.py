# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

"""Alternative admin cli

Provides alternative ceremony, metadata update, and sign admin cli commands.

"""

from repository_service_tuf.cli import click, rstuf


@rstuf.group()  # type: ignore
def admin2():
    """Alternative admin interface"""


@admin2.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """
