# SPDX-License-Identifier: MIT

from click import Context

from repository_service_tuf.cli import click, rstuf


@rstuf.group()
@click.pass_context
def task(context: Context):
    """Task Management Commands"""
