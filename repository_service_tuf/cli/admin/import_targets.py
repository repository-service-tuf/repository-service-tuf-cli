import json
import os
from datetime import datetime
from typing import Any, Dict, List

from rich.console import Console

from repository_service_tuf.cli import click
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.helpers.api_client import (
    Methods,
    bootstrap_status,
    publish_targets,
    request_server,
    task_status,
)
from repository_service_tuf.helpers.tuf import (
    Delegations,
    Metadata,
    SuccinctRoles,
    Targets,
)

console = Console()


def _check_csv_files(csv_files: List[str]):
    not_found_csv_files: List[str] = []
    for csv_file in csv_files:
        if not os.path.isfile(csv_file):
            not_found_csv_files.append(csv_file)

    if len(not_found_csv_files) > 0:
        raise click.ClickException(
            f"CSV file(s) not found: {(', ').join(not_found_csv_files)}"
        )


def _parse_csv_data(
    csv_file: str, succinct_roles: SuccinctRoles
) -> List[Dict[str, Any]]:
    rstuf_db_data: List[Dict[str, Any]] = []
    with open(csv_file, "r") as f:
        for line in f:
            rstuf_db_data.append(
                {
                    "path": line.split(";")[0],
                    "info": {
                        "length": int(line.split(";")[1]),
                        "hashes": {line.split(";")[2]: line.split(";")[3]},
                    },
                    "rolename": succinct_roles.get_role_for_target(
                        line.split(";")[0]
                    ),
                    "published": False,
                    "action": "ADD",
                    "last_update": datetime.now(),
                }
            )

    return rstuf_db_data


def _import_csv_to_rstuf(
    db_client: Any,
    rstuf_table: Any,
    csv_files: List[str],
    succinct_roles: SuccinctRoles,
) -> None:
    # Required to except the appropriate exception.
    from sqlalchemy.exc import IntegrityError

    for csv_file in csv_files:
        console.print(f"Import status: Loading data from {csv_file}")
        rstuf_db_data = _parse_csv_data(csv_file, succinct_roles)
        console.print(f"Import status: Importing {csv_file} data")
        try:
            db_client.execute(rstuf_table.insert(), rstuf_db_data)
        except IntegrityError:
            raise click.ClickException(
                "Import status: ABORTED due duplicated targets. "
                "CSV files must to have unique targets (path). "
                "No data added to RSTUF DB."
            )
        console.print(f"Import status: {csv_file} imported")


def _get_succinct_roles(metadata_url: str) -> SuccinctRoles:
    response = request_server(metadata_url, "1.bin.json", Methods.get)
    if response.status_code == 404:
        raise click.ClickException("RSTUF Metadata Targets not found.")

    json_data = json.loads(response.text)
    targets: Metadata[Targets] = Metadata.from_dict(json_data)
    if targets.signed.delegations is None:
        raise click.ClickException("Failed to get Targets Delegations")

    targets_delegations: Delegations = targets.signed.delegations

    if targets_delegations.succinct_roles is None:
        raise click.ClickException("Failed to get Targets succinct roles")

    return targets_delegations.succinct_roles


@admin.command()
@click.option(
    "--metadata-url",
    required=True,
    help="RSTUF Metadata URL i.e.: http://127.0.0.1 .",
)
@click.option(
    "--db-uri",
    required=True,
    help="RSTUF DB URI. i.e.: postgresql://postgres:secret@127.0.0.1:5433",
)
@click.option(
    "--csv",
    required=True,
    multiple=True,
    help=(
        "CSV file to import. Multiple --csv parameters are allowed. "
        "See rstuf CLI guide for more details."
    ),
)
@click.option(
    "--skip-publish-targets",
    is_flag=True,
    help="Skip publishing targets in TUF Metadata.",
)
@click.pass_context
def import_targets(
    context: Any,
    metadata_url: str,
    db_uri: str,
    csv: List[str],
    skip_publish_targets: bool,
):
    """
    Import targets to RSTUF from exported CSV file.\n
    Note: sqlalchemy needs to be installed in order to use this command.\n
    pip install repository-service-tuf[sqlalchemy,psycopg2]
    """

    # SQLAlchemy is an optional dependency and is required only for users who
    # want to use import_targets. That's why we have import it here.
    try:
        from sqlalchemy import Connection, MetaData, Table, create_engine
    except ModuleNotFoundError:
        raise ModuleNotFoundError(
            "SQLAlchemy is required by import-targets. "
            "pip install repository-service-tuf[sqlalchemy,psycopg2]"
        )

    settings = context.obj["settings"]

    bs_status = bootstrap_status(settings)
    if bs_status.get("data", {}).get("bootstrap") is False:
        raise click.ClickException(
            "`import-targets` requires bootstrap process done. "
            f"{bs_status.get('message')}"
        )

    # load all required infrastructure
    succinct_roles = _get_succinct_roles(metadata_url)
    engine = create_engine(f"{db_uri}")
    db_metadata = MetaData()
    db_client: Connection = engine.connect()
    rstuf_table = Table("rstuf_targets", db_metadata, autoload_with=engine)

    # validate if the CSV files are accessible
    _check_csv_files(csv_files=csv)
    # import all CSV file(s) data to RSTUF DB without commiting
    _import_csv_to_rstuf(db_client, rstuf_table, csv, succinct_roles)

    # commit data into RSTUF DB
    console.print("Import status: Commiting all data to the RSTUF database")
    db_client.commit()
    console.print("Import status: All data imported to RSTUF DB")

    if skip_publish_targets:
        console.print(
            "Import status: Finished. "
            "Not targets published (`--skip-publish-targets`)"
        )
    else:
        console.print("Import status: Submitting action publish targets")
        task_id = publish_targets(settings)
        console.print(f"Import status: Publish targets task id is {task_id}")
        # monitor task status
        result = task_status(task_id, settings, "Import status: task ")
        if result is not None:
            console.print("Import status: [green]Finished.[/]")
