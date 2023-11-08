import json
import os
from datetime import datetime
from math import log
from typing import Any, Dict, List

from tuf.api.metadata import SuccinctRoles

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    bootstrap_status,
    publish_targets,
    request_server,
    task_status,
)


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
    db: Any,
    rstuf_target_roles: Any,
    succinct_roles: SuccinctRoles,
    csv_file: str,
) -> List[Dict[str, Any]]:
    rstuf_db_data: List[Dict[str, Any]] = []
    with open(csv_file, "r") as f:
        for line in f:
            path = line.split(";")[0]
            length = int(line.split(";")[1])
            hash_algorithm = line.split(";")[2]
            hash_digest = line.split(";")[3]
            rstuf_db_data.append(
                {
                    "path": path,
                    "info": {
                        "length": length,
                        "hashes": {hash_algorithm: hash_digest},
                    },
                    "published": False,
                    "action": "ADD",
                    "targets_role": db.execute(
                        rstuf_target_roles.select().where(
                            rstuf_target_roles.c.rolename
                            == succinct_roles.get_role_for_target(path)
                        )
                    ).one()[0],
                    "last_update": datetime.now(),
                }
            )

    return rstuf_db_data


def _import_csv_to_rstuf(
    db_client: Any,
    rstuf_target_files: Any,
    rstuf_target_roles: Any,
    csv_files: List[str],
    succinct_roles: SuccinctRoles,
) -> None:
    # Required to except the appropriate exception.
    from sqlalchemy.exc import IntegrityError

    for csv_file in csv_files:
        console.print(f"Import status: Loading data from {csv_file}")
        rstuf_db_data = _parse_csv_data(
            db_client, rstuf_target_roles, succinct_roles, csv_file
        )
        console.print(f"Import status: Importing {csv_file} data")
        try:
            db_client.execute(rstuf_target_files.insert(), rstuf_db_data)
        except IntegrityError:
            raise click.ClickException(
                "Import status: ABORTED due duplicated artifacts. "
                "CSV files must to have unique artifacts (path). "
                "No data added to RSTUF DB."
            )
        console.print(f"Import status: {csv_file} imported")


def _get_succinct_roles(api_server: str) -> SuccinctRoles:
    response = request_server(api_server, URL.CONFIG.value, Methods.GET)
    if response.status_code != 200:
        raise click.ClickException(
            f"Failed to retrieve RSTUF config {response.text}"
        )

    try:
        data = response.json()["data"]
        num_bins = data["number_of_delegated_bins"]

    except (json.JSONDecodeError, KeyError):
        raise click.ClickException(
            "Failed to parse 'data', 'number_of_delegated_bins' from config "
            f"{response.text}"
        )
    bit_length = int(log(num_bins, 2))

    # the 'keyids' and the 'threshold' are irrelevant once we need the names
    succinct_roles = SuccinctRoles(
        keyids=[], threshold=1, bit_length=bit_length, name_prefix="bins"
    )

    return succinct_roles


@admin.command()  # type: ignore
@click.option(
    "--api-server",
    required=False,
    help="RSTUF API URL i.e.: http://127.0.0.1 .",
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
    "--skip-publish-artifacts",
    is_flag=True,
    help="Skip publishing artifacts in TUF Metadata.",
)
@click.pass_context
def import_artifacts(
    context: Any,
    api_server: str,
    db_uri: str,
    csv: List[str],
    skip_publish_artifacts: bool,
):
    """
    Import artifacts to RSTUF from exported CSV file.\n
    Note: sqlalchemy needs to be installed in order to use this command.\n
    pip install repository-service-tuf[sqlalchemy,psycopg2]
    """

    # SQLAlchemy is an optional dependency and is required only for users who
    # want to use import_artifacts. That's why we have import it here.
    try:
        from sqlalchemy import Connection, MetaData, Table, create_engine
    except ModuleNotFoundError:
        raise ModuleNotFoundError(
            "SQLAlchemy is required by import-artifacts. "
            "pip install repository-service-tuf[sqlalchemy,psycopg2]"
        )
    settings = context.obj["settings"]
    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        raise click.ClickException(
            "Requires '--api-server' "
            "Example: --api-server https://api.rstuf.example.com"
        )

    bs_status = bootstrap_status(settings)
    if bs_status.get("data", {}).get("bootstrap") is False:
        raise click.ClickException(
            "`import-artifacts` requires bootstrap process done. "
            f"{bs_status.get('message')}"
        )

    # load all required infrastructure
    succinct_roles = _get_succinct_roles(api_server)
    engine = create_engine(f"{db_uri}")
    db_metadata = MetaData()
    db_client: Connection = engine.connect()
    rstuf_target_files = Table(
        "rstuf_target_files", db_metadata, autoload_with=engine
    )
    rstuf_target_roles = Table(
        "rstuf_target_roles", db_metadata, autoload_with=engine
    )

    # validate if the CSV files are accessible
    _check_csv_files(csv_files=csv)
    # import all CSV file(s) data to RSTUF DB without commiting
    _import_csv_to_rstuf(
        db_client, rstuf_target_files, rstuf_target_roles, csv, succinct_roles
    )

    # commit data into RSTUF DB
    console.print("Import status: Commiting all data to the RSTUF database")
    db_client.commit()
    console.print("Import status: All data imported to RSTUF DB")

    if skip_publish_artifacts:
        console.print(
            "Import status: Finished. "
            "No artifacts published (`--skip-publish-artifacts`)"
        )
    else:
        console.print("Import status: Submitting action publish artifacts")
        task_id = publish_targets(settings)
        console.print(f"Import status: Publish artifacts task id is {task_id}")
        # monitor task status
        result = task_status(task_id, settings, "Import status: task ")
        if result is not None:
            console.print("Import status: [green]Finished.[/]")
