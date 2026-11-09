# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import datetime
import sys
from datetime import timezone
from types import ModuleType
from unittest.mock import MagicMock, patch

import click
import pretend
import pytest
from repository_service_tuf.cli.admin import import_artifacts

from tests.conftest import invoke_command

try:
    import sqlalchemy  # noqa: F401

    HAS_SQLALCHEMY = True
except ModuleNotFoundError:
    HAS_SQLALCHEMY = False

require_sqlalchemy = pytest.mark.skipif(
    not HAS_SQLALCHEMY,
    reason="SQLAlchemy is not installed (run pip install .[sqlalchemy])",
)


SRC_PATH = "repository_service_tuf.cli.admin.import_artifacts"


class TestImportArtifactsFunctions:
    def test__check_csv_files(self, monkeypatch):
        monkeypatch.setattr(
            import_artifacts.os.path,
            "isfile",
            pretend.call_recorder(lambda *a: True),
        )

        result = import_artifacts._check_csv_files(["1of2.csv", "2of2.csv"])
        assert result is None
        assert import_artifacts.os.path.isfile.calls == [
            pretend.call("1of2.csv"),
            pretend.call("2of2.csv"),
        ]

    def test__check_csv_files_file_not_found(self, monkeypatch):
        monkeypatch.setattr(
            import_artifacts.os.path,
            "isfile",
            pretend.call_recorder(lambda *a: False),
        )

        with pytest.raises(import_artifacts.click.ClickException) as err:
            import_artifacts._check_csv_files(["1of2.csv", "2of2.csv"])

        assert "CSV file(s) not found: 1of2.csv, 2of2.csv" in str(err)
        assert import_artifacts.os.path.isfile.calls == [
            pretend.call("1of2.csv"),
            pretend.call("2of2.csv"),
        ]

    def test__parse_csv_data(self, monkeypatch):
        fake_data = [
            "path/file1;123;blake2b-256;hash1",
            "path/file2;456;blake2b-256;hash2",
        ]
        db = pretend.stub(
            execute=pretend.call_recorder(
                lambda *a: pretend.stub(
                    one=pretend.call_recorder(lambda: [15])
                )
            )
        )
        succinct_roles = pretend.stub(
            get_role_for_target=pretend.call_recorder(lambda *a: "bins-e")
        )
        rstuf_target_roles = pretend.stub(
            c=pretend.stub(rolename="bins-e"),
            select=pretend.call_recorder(
                lambda: pretend.stub(
                    where=pretend.call_recorder(lambda *a: True)
                )
            ),
        )
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: fake_data),
        )
        monkeypatch.setitem(
            import_artifacts.__builtins__, "open", lambda *a: fake_file_obj
        )

        fake_time = datetime.datetime(
            2019, 6, 16, 9, 5, 1, tzinfo=timezone.utc
        )
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda a: fake_time)
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.datetime",
            fake_datetime,
        )
        succinct_roles = pretend.stub(
            get_role_for_target=pretend.call_recorder(lambda *a: "bins-a")
        )

        result = import_artifacts._parse_csv_data(
            db, rstuf_target_roles, succinct_roles, "fake_file"
        )

        assert result == [
            {
                "path": "path/file1",
                "info": {"length": 123, "hashes": {"blake2b-256": "hash1"}},
                "targets_role": 15,
                "published": False,
                "action": "ADD",
                "last_update": fake_time,
            },
            {
                "path": "path/file2",
                "info": {"length": 456, "hashes": {"blake2b-256": "hash2"}},
                "targets_role": 15,
                "published": False,
                "action": "ADD",
                "last_update": fake_time,
            },
        ]
        assert db.execute.calls == [pretend.call(True), pretend.call(True)]
        assert succinct_roles.get_role_for_target.calls == [
            pretend.call("path/file1"),
            pretend.call("path/file2"),
        ]

    def test_import_csv_to_rstuf_success(self, monkeypatch):
        """Test successful execution of _import_csv_to_rstuf."""
        import sys

        db_client = MagicMock()
        rstuf_target_files = MagicMock()
        rstuf_target_roles = MagicMock()
        csv_files = ["artifacts.csv"]
        succinct_roles = MagicMock()
        mock_parsed_data = [{"path": "file1.txt"}]

        monkeypatch.setitem(
            sys.modules, "sqlalchemy.exc", MagicMock(IntegrityError=Exception)
        )

        with (
            patch(
                f"{SRC_PATH}._parse_csv_data", return_value=mock_parsed_data
            ),
            patch(f"{SRC_PATH}.console.print"),
        ):

            import_artifacts._import_csv_to_rstuf(
                db_client,
                rstuf_target_files,
                rstuf_target_roles,
                csv_files,
                succinct_roles,
            )
            db_client.execute.assert_called_once()

    def test_import_csv_to_rstuf_integrity_error(self, monkeypatch):
        """Test _import_csv_to_rstuf raises ClickException on IntegrityError (lines 92-97)."""

        # Create a realistic mock module structure for sqlalchemy and sqlalchemy.exc
        sa_module = ModuleType("sqlalchemy")
        sa_exc_module = ModuleType("sqlalchemy.exc")

        class MockIntegrityError(Exception):
            pass

        sa_exc_module.IntegrityError = MockIntegrityError

        monkeypatch.setitem(sys.modules, "sqlalchemy", sa_module)
        monkeypatch.setitem(sys.modules, "sqlalchemy.exc", sa_exc_module)

        db_client = MagicMock()
        db_client.execute.side_effect = MockIntegrityError("duplicate path")

        rstuf_target_files = MagicMock()
        rstuf_target_roles = MagicMock()
        csv_files = ["artifacts.csv"]
        succinct_roles = MagicMock()
        mock_parsed_data = [{"path": "file1.txt"}]

        with (
            patch(
                f"{SRC_PATH}._parse_csv_data", return_value=mock_parsed_data
            ),
            patch(f"{SRC_PATH}.console.print"),
            pytest.raises(
                click.ClickException, match="ABORTED due duplicated artifacts"
            ),
        ):
            import_artifacts._import_csv_to_rstuf(
                db_client,
                rstuf_target_files,
                rstuf_target_roles,
                csv_files,
                succinct_roles,
            )

    @require_sqlalchemy
    def test__import_csv_to_rstuf(self):
        fake_rstuf_files = pretend.stub(
            insert=pretend.call_recorder(lambda: None)
        )
        fake_db_client = pretend.stub(
            execute=pretend.call_recorder(lambda *a: None)
        )
        import_artifacts._parse_csv_data = pretend.call_recorder(
            lambda *a: [{"k1": "v1", "k2": "v2"}]
        )

        result = import_artifacts._import_csv_to_rstuf(
            fake_db_client,
            fake_rstuf_files,
            "fake_rstuf_roles",
            ["csv1", "csv2"],
            "fake_succinct_roles",
        )

        assert result is None
        assert import_artifacts._parse_csv_data.calls == [
            pretend.call(
                fake_db_client,
                "fake_rstuf_roles",
                "fake_succinct_roles",
                "csv1",
            ),
            pretend.call(
                fake_db_client,
                "fake_rstuf_roles",
                "fake_succinct_roles",
                "csv2",
            ),
        ]
        assert fake_db_client.execute.calls == [
            pretend.call(None, [{"k1": "v1", "k2": "v2"}]),
            pretend.call(None, [{"k1": "v1", "k2": "v2"}]),
        ]
        assert fake_rstuf_files.insert.calls == [
            pretend.call(),
            pretend.call(),
        ]

    @require_sqlalchemy
    def test__import_csv_to_rstuf_duplicate_artifacts(self):
        # Required to raise an exception type from import inside a function
        from sqlalchemy.exc import IntegrityError

        fake_rstuf_files = pretend.stub(
            insert=pretend.raiser(IntegrityError("Duplicate", "param", "orig"))
        )
        fake_db_client = pretend.stub(
            execute=pretend.call_recorder(lambda *a: None)
        )
        import_artifacts._parse_csv_data = pretend.call_recorder(
            lambda *a: [{"k1": "v1", "k2": "v2"}]
        )

        with pytest.raises(import_artifacts.click.ClickException) as err:
            import_artifacts._import_csv_to_rstuf(
                fake_db_client,
                fake_rstuf_files,
                "fake_rstuf_roles",
                ["csv1", "csv2"],
                "fake_succinct_roles",
            )
        assert "ABORTED due duplicated artifacts." in str(err)
        assert import_artifacts._parse_csv_data.calls == [
            pretend.call(
                fake_db_client,
                "fake_rstuf_roles",
                "fake_succinct_roles",
                "csv1",
            ),
        ]

    def test__get_succinct_roles(self):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(
                lambda: {"data": {"number_of_delegated_bins": 16}}
            ),
        )
        import_artifacts.request_server = pretend.call_recorder(
            lambda *a: fake_response
        )
        import_artifacts.SuccinctRoles = pretend.call_recorder(
            lambda **kw: "fake_succinct_roles"
        )

        result = import_artifacts._get_succinct_roles("http://127.0.0.1")
        assert result == "fake_succinct_roles"
        assert import_artifacts.request_server.calls == [
            pretend.call(
                "http://127.0.0.1",
                import_artifacts.URL.CONFIG.value,
                import_artifacts.Methods.GET,
            )
        ]
        assert import_artifacts.SuccinctRoles.calls == [
            pretend.call(
                keyids=[], threshold=1, bit_length=4, name_prefix="bins"
            )
        ]
        assert fake_response.json.calls == [pretend.call()]

    def test__get_succinct_roles_failed_retrieve_config(self):
        import_artifacts.request_server = pretend.call_recorder(
            lambda *a: pretend.stub(status_code=404, text="Not found")
        )

        with pytest.raises(import_artifacts.click.ClickException) as err:
            import_artifacts._get_succinct_roles("http://127.0.0.1/metadata")
        assert "Failed to retrieve RSTUF config" in str(err)

    def test__get_succinct_roles_failed_parsing(self, monkeypatch):
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"data": {}}),
            text="{'data': {}}",
        )
        import_artifacts.request_server = pretend.call_recorder(
            lambda *a: fake_response
        )

        with pytest.raises(import_artifacts.click.ClickException) as err:
            import_artifacts._get_succinct_roles("http://127.0.0.1")
        assert "Failed to parse 'data', 'number_of_delegated_bins'" in str(err)
        assert import_artifacts.request_server.calls == [
            pretend.call(
                "http://127.0.0.1",
                import_artifacts.URL.CONFIG.value,
                import_artifacts.Methods.GET,
            )
        ]
        assert fake_response.json.calls == [pretend.call()]


class TestImportArtifactsGroupCLI:
    @require_sqlalchemy
    def test_import_artifacts(self, test_context):
        # Required to properly mock functions imported inside import_artifacts
        import sqlalchemy

        import_artifacts.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": True}, "message": "some msg"}
        )
        import_artifacts._get_succinct_roles = pretend.call_recorder(
            lambda *a: "fake_succinct_roles"
        )
        sqlalchemy.create_engine = pretend.call_recorder(
            lambda *a: pretend.stub(
                connect=pretend.call_recorder(
                    lambda: pretend.stub(
                        commit=pretend.call_recorder(lambda: None)
                    )
                )
            )
        )
        sqlalchemy.Table = pretend.call_recorder(
            lambda *a, **kw: "rstuf_table"
        )
        import_artifacts._check_csv_files = pretend.call_recorder(
            lambda **kw: None
        )
        import_artifacts._import_csv_to_rstuf = pretend.call_recorder(
            lambda *a: None
        )
        import_artifacts.publish_artifacts = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        import_artifacts.task_status = pretend.call_recorder(
            lambda *a: {"status": "SUCCESS"}
        )

        args = [
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        test_context["settings"].SERVER = "http://127.0.0.1"

        result = invoke_command(
            import_artifacts.import_artifacts, [], args, test_context
        )
        assert result.exit_code == 0, result.output
        assert "Finished." in result.output
        assert import_artifacts.bootstrap_status.calls == [
            pretend.call(result.context["settings"])
        ]
        assert import_artifacts._get_succinct_roles.calls == [
            pretend.call("http://127.0.0.1")
        ]
        assert sqlalchemy.create_engine.calls == [
            pretend.call("postgresql://postgres:secret@127.0.0.1:5433")
        ]
        assert import_artifacts._check_csv_files.calls == [
            pretend.call(csv_files=("artifacts1of2.csv", "artifacts2of2.csv"))
        ]
        assert import_artifacts.publish_artifacts.calls == [
            pretend.call(result.context["settings"])
        ]
        assert import_artifacts.task_status.calls == [
            pretend.call(
                "fake_task_id",
                result.context["settings"],
                "Import status: task ",
            )
        ]

    @require_sqlalchemy
    def test_import_artifacts_no_api_server_config_no_param(self):
        args = [
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        result = invoke_command(
            import_artifacts.import_artifacts, [], args, std_err_empty=False
        )
        assert result.exit_code == 1, result.output
        assert "Requires '--api-server' " in result.stderr

    @require_sqlalchemy
    def test_import_artifacts_skip_publish_artifacts(self, test_context):
        # Required to properly mock functions imported inside import_artifacts
        import sqlalchemy

        import_artifacts.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": True}, "message": "some msg"}
        )
        import_artifacts._get_succinct_roles = pretend.call_recorder(
            lambda *a: "fake_succinct_roles"
        )
        sqlalchemy.create_engine = pretend.call_recorder(
            lambda *a: pretend.stub(
                connect=pretend.call_recorder(
                    lambda: pretend.stub(
                        commit=pretend.call_recorder(lambda: None)
                    )
                )
            )
        )
        sqlalchemy.Table = pretend.call_recorder(
            lambda *a, **kw: "rstuf_table"
        )
        import_artifacts._check_csv_files = pretend.call_recorder(
            lambda **kw: None
        )
        import_artifacts._import_csv_to_rstuf = pretend.call_recorder(
            lambda *a: None
        )
        import_artifacts.publish_artifacts = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        import_artifacts.task_status = pretend.call_recorder(
            lambda *a: {"status": "SUCCESS"}
        )

        args = [
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
            "--skip-publish-artifacts",
        ]
        test_context["settings"].SERVER = "http://127.0.0.1"

        result = invoke_command(
            import_artifacts.import_artifacts, [], args, test_context
        )
        assert result.exit_code == 0, result.output
        assert "Finished." in result.output
        assert "No artifacts published" in result.output
        assert import_artifacts.bootstrap_status.calls == [
            pretend.call(result.context["settings"])
        ]
        assert import_artifacts._get_succinct_roles.calls == [
            pretend.call("http://127.0.0.1")
        ]
        assert sqlalchemy.create_engine.calls == [
            pretend.call("postgresql://postgres:secret@127.0.0.1:5433")
        ]
        assert import_artifacts._check_csv_files.calls == [
            pretend.call(csv_files=("artifacts1of2.csv", "artifacts2of2.csv"))
        ]
        assert import_artifacts.publish_artifacts.calls == []
        assert import_artifacts.task_status.calls == []

    def test_import_artifacts_sqlalchemy_import_fails(self, test_context):
        import builtins

        real_import = builtins.__import__
        # We need to raise an exception only when "sqlalchemy" is imported
        # otherwise client.invoke() will fail before reaching import_targets

        def fake_import(name, *args, **kwargs):
            if name == "sqlalchemy":
                raise ModuleNotFoundError()

            return real_import(name, *args, **kwargs)

        builtins.__import__ = fake_import

        args = ["--db-uri", "", "--csv", ""]
        test_context["settings"].SERVER = ""
        with pytest.raises(ModuleNotFoundError) as exc:
            invoke_command(
                import_artifacts.import_artifacts,
                [],
                args,
                test_context,
                std_err_empty=False,
            )

        # Return the original import to not cause other exceptions.
        builtins.__import__ = real_import
        assert "pip install repository-service-tuf[sqlalchemy" in str(exc)

    @require_sqlalchemy
    def test_import_artifacts_bootstrap_check_failed(self, test_context):

        import_artifacts.bootstrap_status = pretend.raiser(
            import_artifacts.click.ClickException("Server ERROR")
        )

        args = [
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        test_context["settings"].SERVER = "http://127.0.0.1"

        result = invoke_command(
            import_artifacts.import_artifacts,
            [],
            args,
            test_context,
            std_err_empty=False,
        )
        assert result.exit_code == 1
        assert "Server ERROR" in result.stderr, result.stderr

    @require_sqlalchemy
    def test_import_artifacts_without_bootstrap(self, test_context):

        import_artifacts.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": False}, "message": "some msg"}
        )

        args = [
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        test_context["settings"].SERVER = "http://127.0.0.1"

        result = invoke_command(
            import_artifacts.import_artifacts,
            [],
            args,
            test_context,
            std_err_empty=False,
        )
        assert result.exit_code == 1, result.output
        assert (
            "import-artifacts` requires bootstrap process done."
            in result.stderr
        )
        assert import_artifacts.bootstrap_status.calls == [
            pretend.call(result.context["settings"])
        ]

    def test_import_artifacts_command_success(self, monkeypatch):
        """Test successful execution of import_artifacts command."""
        import sys

        args = ["--db-uri", "sqlite:///:memory:", "--csv", "artifacts.csv"]

        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value = mock_conn

        mock_sqlalchemy = MagicMock()
        mock_sqlalchemy.create_engine.return_value = mock_engine
        mock_sqlalchemy.Table = MagicMock()
        monkeypatch.setitem(sys.modules, "sqlalchemy", mock_sqlalchemy)

        monkeypatch.setattr(
            f"{SRC_PATH}._get_succinct_roles", lambda server_url: MagicMock()
        )
        monkeypatch.setattr(
            f"{SRC_PATH}._check_csv_files", lambda *args, **kwargs: None
        )
        monkeypatch.setattr(
            f"{SRC_PATH}._import_csv_to_rstuf", lambda *args, **kwargs: None
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.bootstrap_status",
            lambda *args, **kwargs: {"data": {"bootstrap": True}},
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.publish_artifacts",
            lambda *args, **kwargs: "task-id-456",
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.task_status", lambda *args, **kwargs: "completed"
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.console.print", lambda *args, **kwargs: None
        )

        # Use a MagicMock or an object with attributes for settings so settings.SERVER works
        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: (
            "https://api.rstuf.example.com" if key == "SERVER" else default
        )
        mock_settings.SERVER = "https://api.rstuf.example.com"

        test_context = {"settings": mock_settings}

        result = invoke_command(
            import_artifacts.import_artifacts,
            [],
            args,
            test_context=test_context,
        )

        assert result.exit_code == 0
        mock_conn.commit.assert_called_once()

    def test_import_artifacts_missing_server(self, monkeypatch):
        """Test import_artifacts raises ClickException when SERVER config is missing."""
        import sys

        args = ["--db-uri", "sqlite:///:memory:", "--csv", "artifacts.csv"]

        # Mock sqlalchemy so the optional import check succeeds
        mock_sqlalchemy = MagicMock()
        mock_sqlalchemy.create_engine.return_value = MagicMock()
        mock_sqlalchemy.Table = MagicMock()
        monkeypatch.setitem(sys.modules, "sqlalchemy", mock_sqlalchemy)

        test_context = {"settings": {}}  # No SERVER configured

        result = invoke_command(
            import_artifacts.import_artifacts,
            [],
            args,
            test_context=test_context,
            std_err_empty=False,
        )
        assert result.exit_code != 0
        assert "Requires '--api-server'" in result.output

    def test_import_artifacts_not_bootstrapped(self, monkeypatch):
        """Test import_artifacts raises ClickException when bootstrap is False (lines 186-189)."""
        import sys

        args = ["--db-uri", "sqlite:///:memory:", "--csv", "artifacts.csv"]

        mock_sqlalchemy = MagicMock()
        monkeypatch.setitem(sys.modules, "sqlalchemy", mock_sqlalchemy)

        # Mock bootstrap_status to return bootstrap = False
        monkeypatch.setattr(
            f"{SRC_PATH}.bootstrap_status",
            lambda *args, **kwargs: {
                "data": {"bootstrap": False},
                "message": "Not bootstrapped",
            },
        )

        test_context = {
            "settings": {"SERVER": "https://api.rstuf.example.com"}
        }

        result = invoke_command(
            import_artifacts.import_artifacts,
            [],
            args,
            test_context=test_context,
            std_err_empty=False,
        )
        assert result.exit_code != 0
        assert "requires bootstrap process done" in result.output

    def test_import_artifacts_skip_publish(self, monkeypatch):
        """Test import_artifacts execution with --skip-publish-artifacts flag (lines 216-218)."""
        import sys

        args = [
            "--db-uri",
            "sqlite:///:memory:",
            "--csv",
            "artifacts.csv",
            "--skip-publish-artifacts",
        ]

        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value = mock_conn

        mock_sqlalchemy = MagicMock()
        mock_sqlalchemy.create_engine.return_value = mock_engine
        mock_sqlalchemy.Table = MagicMock()
        monkeypatch.setitem(sys.modules, "sqlalchemy", mock_sqlalchemy)

        mock_settings = MagicMock()
        mock_settings.get.side_effect = lambda key, default=None: (
            "https://api.rstuf.example.com" if key == "SERVER" else default
        )
        mock_settings.SERVER = "https://api.rstuf.example.com"

        monkeypatch.setattr(
            f"{SRC_PATH}._get_succinct_roles", lambda server_url: MagicMock()
        )
        monkeypatch.setattr(
            f"{SRC_PATH}._check_csv_files", lambda *args, **kwargs: None
        )
        monkeypatch.setattr(
            f"{SRC_PATH}._import_csv_to_rstuf", lambda *args, **kwargs: None
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.bootstrap_status",
            lambda *args, **kwargs: {"data": {"bootstrap": True}},
        )
        monkeypatch.setattr(
            f"{SRC_PATH}.console.print", lambda *args, **kwargs: None
        )

        test_context = {"settings": mock_settings}

        result = invoke_command(
            import_artifacts.import_artifacts,
            [],
            args,
            test_context=test_context,
        )

        assert result.exit_code == 0
        mock_conn.commit.assert_called_once()
