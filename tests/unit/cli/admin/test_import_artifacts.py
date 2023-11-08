import datetime

import pretend
import pytest

from repository_service_tuf.cli.admin import import_artifacts


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

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf.cli.admin.import_artifacts.datetime",
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
                "last_update": datetime.datetime(2019, 6, 16, 9, 5, 1),
            },
            {
                "path": "path/file2",
                "info": {"length": 456, "hashes": {"blake2b-256": "hash2"}},
                "targets_role": 15,
                "published": False,
                "action": "ADD",
                "last_update": datetime.datetime(2019, 6, 16, 9, 5, 1),
            },
        ]
        assert db.execute.calls == [pretend.call(True), pretend.call(True)]
        assert succinct_roles.get_role_for_target.calls == [
            pretend.call("path/file1"),
            pretend.call("path/file2"),
        ]

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
    def test_import_artifacts(self, client, test_context):
        # Required to properly mock functions imported inside import_artifacts
        import sqlalchemy

        test_context["settings"].SERVER = "fake-server"

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
        import_artifacts.publish_targets = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        import_artifacts.task_status = pretend.call_recorder(
            lambda *a: {"status": "SUCCESS"}
        )

        options = [
            "--api-server",
            "http://127.0.0.1",
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        result = client.invoke(
            import_artifacts.import_artifacts, options, obj=test_context
        )
        assert result.exit_code == 0, result.output
        assert "Finished." in result.output
        assert import_artifacts.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
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
        assert import_artifacts.publish_targets.calls == [
            pretend.call(test_context["settings"])
        ]
        assert import_artifacts.task_status.calls == [
            pretend.call(
                "fake_task_id",
                test_context["settings"],
                "Import status: task ",
            )
        ]

    def test_import_artifacts_no_api_server_config_no_param(
        self, client, test_context
    ):
        options = [
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        result = client.invoke(
            import_artifacts.import_artifacts, options, obj=test_context
        )
        assert result.exit_code == 1, result.output
        assert "Requires '--api-server' " in result.output

    def test_import_artifacts_skip_publish_targets(self, client, test_context):
        # Required to properly mock functions imported inside import_artifacts
        import sqlalchemy

        test_context["settings"].SERVER = "fake-server"

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
        import_artifacts.publish_targets = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        import_artifacts.task_status = pretend.call_recorder(
            lambda *a: {"status": "SUCCESS"}
        )

        options = [
            "--api-server",
            "http://127.0.0.1",
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
            "--skip-publish-artifacts",
        ]
        result = client.invoke(
            import_artifacts.import_artifacts, options, obj=test_context
        )
        assert result.exit_code == 0, result.output
        assert "Finished." in result.output
        assert "No artifacts published" in result.output
        assert import_artifacts.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
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
        assert import_artifacts.publish_targets.calls == []
        assert import_artifacts.task_status.calls == []

    def test_import_artifacts_sqlalchemy_import_fails(
        self, client, test_context
    ):
        import builtins

        real_import = builtins.__import__
        # We need to raise an exception only when "sqlalchemy" is imported
        # otherwise client.invoke() will fail before reaching import_targets

        def fake_import(name, *args, **kwargs):
            if name == "sqlalchemy":
                raise ModuleNotFoundError()

            return real_import(name, *args, **kwargs)

        builtins.__import__ = fake_import

        test_context["settings"].SERVER = "fake-server"
        options = ["--api-server", "", "--db-uri", "", "--csv", ""]
        result = client.invoke(
            import_artifacts.import_artifacts, options, obj=test_context
        )

        # Return the original import to not cause other exceptions.
        builtins.__import__ = real_import

        assert result.exit_code == 1
        assert isinstance(result.exception, ModuleNotFoundError)
        exc_msg = result.exception.msg
        assert "pip install repository-service-tuf[sqlalchemy" in exc_msg

    def test_import_artifacts_bootstrap_check_failed(
        self, client, test_context
    ):
        test_context["settings"].SERVER = "fake-server"

        import_artifacts.bootstrap_status = pretend.raiser(
            import_artifacts.click.ClickException("Server ERROR")
        )

        options = [
            "--api-server",
            "http://127.0.0.1",
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]

        result = client.invoke(
            import_artifacts.import_artifacts, options, obj=test_context
        )
        assert result.exit_code == 1
        assert "Server ERROR" in result.output, result.output

    def test_import_artifacts_without_bootstrap(self, client, test_context):
        test_context["settings"].SERVER = "fake-server"

        import_artifacts.bootstrap_status = pretend.call_recorder(
            lambda *a: {"data": {"bootstrap": False}, "message": "some msg"}
        )

        options = [
            "--api-server",
            "http://127.0.0.1",
            "--db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "--csv",
            "artifacts1of2.csv",
            "--csv",
            "artifacts2of2.csv",
        ]
        result = client.invoke(
            import_artifacts.import_artifacts, options, obj=test_context
        )
        assert result.exit_code == 1, result.output
        assert (
            "import-artifacts` requires bootstrap process done."
            in result.output
        )
        assert import_artifacts.bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]
