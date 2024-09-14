# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors

# SPDX-License-Identifier: MIT

from repository_service_tuf.cli.admin import admin, click


@admin.group()
@click.pass_context
def delegations(context):
    """
    Delegations management.
    """
