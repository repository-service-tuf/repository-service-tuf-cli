import pytest
import pretend
import datetime
from unittest.mock import Mock

from repository_service_tuf.cli.admin import import_targets


class TestImportTargetsFunctions:
    def test__check_csv_files(self, monkeypatch):
        monkeypatch.setattr(
            import_targets.os.path,
            "isfile",
            pretend.call_recorder(lambda *a: True),
        )

        result = import_targets._check_csv_files(["1of2.csv", "2of2.csv"])
        assert result is None
        assert import_targets.os.path.isfile.calls == [
            pretend.call("1of2.csv"),
            pretend.call("2of2.csv"),
        ]

    def test__check_csv_files_file_not_found(self, monkeypatch):
        monkeypatch.setattr(
            import_targets.os.path,
            "isfile",
            pretend.call_recorder(lambda *a: False),
        )

        with pytest.raises(import_targets.click.ClickException) as err:
            import_targets._check_csv_files(["1of2.csv", "2of2.csv"])

        assert "CSV file(s) not found: 1of2.csv, 2of2.csv" in str(err)
        assert import_targets.os.path.isfile.calls == [
            pretend.call("1of2.csv"),
            pretend.call("2of2.csv"),
        ]

    def test__parse_csv_data(self, monkeypatch):
        fake_data = [
            "path/file1;123;blake2b-256;hash1",
            "path/file2;456;blake2b-256;hash2",
        ]
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
            read=pretend.call_recorder(lambda: fake_data),
        )
        monkeypatch.setitem(
            import_targets.__builtins__, "open", lambda *a, **kw: fake_file_obj
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf.cli.admin.import_targets.datetime",
            fake_datetime,
        )
        succinct_roles = pretend.stub(
            get_role_for_target=pretend.call_recorder(lambda *a: "bins-a")
        )

        result = import_targets._parse_csv_data("fake_file", succinct_roles)

        assert result == [
            {
                "path": "path/file1",
                "info": {"length": 123, "hashes": {"blake2b-256": "hash1"}},
                "rolename": "bins-a",
                "published": False,
                "action": "ADD",
                "last_update": datetime.datetime(2019, 6, 16, 9, 5, 1),
            },
            {
                "path": "path/file2",
                "info": {"length": 456, "hashes": {"blake2b-256": "hash2"}},
                "rolename": "bins-a",
                "published": False,
                "action": "ADD",
                "last_update": datetime.datetime(2019, 6, 16, 9, 5, 1),
            },
        ]

    def test__import_csv_to_rstuf(self):
        fake_rstuf_table = pretend.stub(
            insert=pretend.call_recorder(lambda: None)
        )
        fake_db_client = pretend.stub(
            execute=pretend.call_recorder(lambda *a: None)
        )
        import_targets._parse_csv_data = pretend.call_recorder(
            lambda *a: [{"k1": "v1", "k2": "v2"}]
        )

        result = import_targets._import_csv_to_rstuf(
            fake_db_client,
            fake_rstuf_table,
            ["csv1", "csv2"],
            "fake_succinct_roles",
        )

        assert result is None
        assert import_targets._parse_csv_data.calls == [
            pretend.call("csv1", "fake_succinct_roles"),
            pretend.call("csv2", "fake_succinct_roles"),
        ]
        assert fake_db_client.execute.calls == [
            pretend.call(
                fake_rstuf_table.insert(), [{"k1": "v1", "k2": "v2"}]
            ),
            pretend.call(
                fake_rstuf_table.insert(), [{"k1": "v1", "k2": "v2"}]
            ),
        ]
        assert fake_rstuf_table.insert.calls == [
            pretend.call(),
            pretend.call(),
            pretend.call(),
            pretend.call(),
        ]

    def test__import_csv_to_rstuf_duplicate_targets(self):
        fake_rstuf_table = pretend.stub(
            insert=pretend.raiser(
                import_targets.IntegrityError("Duplicate", "param", "orig")
            )
        )
        fake_db_client = pretend.stub(
            execute=pretend.call_recorder(lambda *a: None)
        )
        import_targets._parse_csv_data = pretend.call_recorder(
            lambda *a: [{"k1": "v1", "k2": "v2"}]
        )

        with pytest.raises(import_targets.click.ClickException) as err:
            import_targets._import_csv_to_rstuf(
                fake_db_client,
                fake_rstuf_table,
                ["csv1", "csv2"],
                "fake_succinct_roles",
            )

        assert "ABORTED due duplicated targets." in str(err)
        assert import_targets._parse_csv_data.calls == [
            pretend.call("csv1", "fake_succinct_roles"),
        ]

    def test__get_succinct_roles(self, monkeypatch):
        import_targets.request_server = pretend.call_recorder(
            lambda *a: pretend.stub(status_code=200, text=b"data")
        )
        monkeypatch.setattr(
            import_targets.json, "loads", lambda *a: "json_data"
        )
        import_targets.Metadata.from_dict = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    delegations=pretend.stub(
                        succinct_roles="fake_succinct_roles"
                    )
                )
            )
        )

        result = import_targets._get_succinct_roles(
            "http://127.0.0.1/metadata"
        )
        assert result == "fake_succinct_roles"

    def test__get_succinct_roles_not_found_metadata(self, monkeypatch):
        import_targets.request_server = pretend.call_recorder(
            lambda *a: pretend.stub(status_code=404, text=b"data")
        )

        with pytest.raises(import_targets.click.ClickException) as err:
            import_targets._get_succinct_roles("http://127.0.0.1/metadata")
        assert "RSTUF Metadata Targets not found." in str(err)

    def test__get_succinct_roles_no_delegations(self, monkeypatch):
        import_targets.request_server = pretend.call_recorder(
            lambda *a: pretend.stub(status_code=200, text=b"data")
        )
        monkeypatch.setattr(
            import_targets.json, "loads", lambda *a: "json_data"
        )
        import_targets.Metadata.from_dict = pretend.call_recorder(
            lambda *a: pretend.stub(signed=pretend.stub(delegations=None))
        )

        with pytest.raises(import_targets.click.ClickException) as err:
            import_targets._get_succinct_roles("http://127.0.0.1/metadata")
        assert "Failed to get Targets Delegations" in str(err)

    def test__get_succinct_roles_no_succinct_roles(self, monkeypatch):
        import_targets.request_server = pretend.call_recorder(
            lambda *a: pretend.stub(status_code=200, text=b"data")
        )
        monkeypatch.setattr(
            import_targets.json, "loads", lambda *a: "json_data"
        )
        import_targets.Metadata.from_dict = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    delegations=pretend.stub(succinct_roles=None)
                )
            )
        )

        with pytest.raises(import_targets.click.ClickException) as err:
            import_targets._get_succinct_roles("http://127.0.0.1/metadata")
        assert "Failed to get Targets succinct roles" in str(err)


class TestImportTargetsGroupCLI:
    def test_import_targets(self, client, test_context):
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        import_targets.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=True)
        )
        import_targets.get_headers = pretend.call_recorder(
            lambda *a: "headers"
        )
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"data": {"bootstrap": True}}),
        )
        import_targets.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        import_targets._get_succinct_roles = pretend.call_recorder(
            lambda *a: "fake_succinct_roles"
        )
        import_targets.create_engine = pretend.call_recorder(
            lambda *a: pretend.stub(
                connect=pretend.call_recorder(
                    lambda: pretend.stub(
                        commit=pretend.call_recorder(lambda: None)
                    )
                )
            )
        )
        import_targets.Table = pretend.call_recorder(
            lambda *a, **kw: "rstuf_table"
        )
        import_targets._check_csv_files = pretend.call_recorder(
            lambda **kw: None
        )
        import_targets._import_csv_to_rstuf = pretend.call_recorder(
            lambda *a: None
        )
        import_targets.publish_targets = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        import_targets.task_status = pretend.call_recorder(
            lambda *a: {"status": "SUCCESS"}
        )

        options = [
            "-metadata-url",
            "http://127.0.0.1/metadata/",
            "-db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "-csv",
            "targets1of2.csv",
            "-csv",
            "targets2of2.csv",
        ]
        result = client.invoke(
            import_targets.import_targets, options, obj=test_context
        )
        assert result.exit_code == 0, result.output
        assert "Finished." in result.output
        assert import_targets.is_logged.calls == [
            pretend.call("fake-server", "test-token")
        ]
        import_targets.request_server.calls == [
            pretend.call(
                "fake-server",
                import_targets.URL.bootstrap.value,
                import_targets.Methods.get,
                headers="headers",
            )
        ]
        assert import_targets.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert fake_response.json.calls == [pretend.call()]
        assert import_targets.create_engine.calls == [
            pretend.call("postgresql://postgres:secret@127.0.0.1:5433")
        ]
        assert import_targets._check_csv_files.calls == [
            pretend.call(csv_files=("targets1of2.csv", "targets2of2.csv"))
        ]
        assert import_targets.publish_targets.calls == [
            pretend.call("fake-server", "headers")
        ]
        assert import_targets.task_status.calls == [
            pretend.call(
                "fake_task_id",
                "fake-server",
                "headers",
                "Import status: task ",
            )
        ]

    def test_import_targets_expired(self, client, test_context):
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        import_targets.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=False, data={"expired": True})
        )

        options = [
            "-metadata-url",
            "http://127.0.0.1/metadata/",
            "-db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "-csv",
            "targets1of2.csv",
            "-csv",
            "targets2of2.csv",
        ]

        result = client.invoke(
            import_targets.import_targets, options, obj=test_context
        )
        assert result.exit_code == 1, result.output
        assert "Try re-login" in result.output

    def test_import_never_logged(self, client, test_context):
        import_targets.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=False, data={"expired": True})
        )

        options = [
            "-metadata-url",
            "http://127.0.0.1/metadata/",
            "-db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "-csv",
            "targets1of2.csv",
            "-csv",
            "targets2of2.csv",
        ]

        result = client.invoke(
            import_targets.import_targets, options, obj=test_context
        )
        assert result.exit_code == 1, result.output
        assert "Login first. Run 'rstuf admin login'" in result.output

    def test_import_targets_bootstrap_check_failed(self, client, test_context):
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        import_targets.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=True)
        )
        import_targets.get_headers = pretend.call_recorder(
            lambda *a: "headers"
        )
        fake_response = pretend.stub(
            status_code=500,
            text="Internal Error",
        )
        import_targets.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )

        options = [
            "-metadata-url",
            "http://127.0.0.1/metadata/",
            "-db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "-csv",
            "targets1of2.csv",
            "-csv",
            "targets2of2.csv",
        ]
        result = client.invoke(
            import_targets.import_targets, options, obj=test_context
        )
        assert result.exit_code == 1, result.output
        assert "Error 500 Internal Error" in result.output
        assert import_targets.is_logged.calls == [
            pretend.call("fake-server", "test-token")
        ]
        assert import_targets.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        import_targets.request_server.calls == [
            pretend.call(
                "fake-server",
                import_targets.URL.bootstrap.value,
                import_targets.Methods.get,
                headers="headers",
            )
        ]

    def test_import_targets_without_bootstrap(self, client, test_context):
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        import_targets.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=True)
        )
        import_targets.get_headers = pretend.call_recorder(
            lambda *a: "headers"
        )
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"data": {"bootstrap": False}}),
        )
        import_targets.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )

        options = [
            "-metadata-url",
            "http://127.0.0.1/metadata/",
            "-db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "-csv",
            "targets1of2.csv",
            "-csv",
            "targets2of2.csv",
        ]
        result = client.invoke(
            import_targets.import_targets, options, obj=test_context
        )
        assert result.exit_code == 1, result.output
        assert (
            "import-targets` requires bootstrap process done." in result.output
        )
        assert import_targets.is_logged.calls == [
            pretend.call("fake-server", "test-token")
        ]
        assert import_targets.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        import_targets.request_server.calls == [
            pretend.call(
                "fake-server",
                import_targets.URL.bootstrap.value,
                import_targets.Methods.get,
                headers="headers",
            )
        ]

    def test_import_targets_skip_publish_targets(self, client, test_context):
        test_context["settings"].SERVER = "fake-server"
        test_context["settings"].TOKEN = "test-token"

        import_targets.is_logged = pretend.call_recorder(
            lambda *a: pretend.stub(state=True)
        )
        import_targets.get_headers = pretend.call_recorder(
            lambda *a: "headers"
        )
        fake_response = pretend.stub(
            status_code=200,
            json=pretend.call_recorder(lambda: {"data": {"bootstrap": True}}),
        )
        import_targets.request_server = pretend.call_recorder(
            lambda *a, **kw: fake_response
        )
        import_targets._get_succinct_roles = pretend.call_recorder(
            lambda *a: "fake_succinct_roles"
        )
        import_targets.create_engine = pretend.call_recorder(
            lambda *a: pretend.stub(
                connect=pretend.call_recorder(
                    lambda: pretend.stub(
                        commit=pretend.call_recorder(lambda: None)
                    )
                )
            )
        )
        import_targets.Table = pretend.call_recorder(
            lambda *a, **kw: "rstuf_table"
        )
        import_targets._check_csv_files = pretend.call_recorder(
            lambda **kw: None
        )
        import_targets._import_csv_to_rstuf = pretend.call_recorder(
            lambda *a: None
        )
        import_targets.publish_targets = pretend.call_recorder(
            lambda *a: "fake_task_id"
        )
        import_targets.task_status = pretend.call_recorder(
            lambda *a: {"status": "SUCCESS"}
        )

        options = [
            "-metadata-url",
            "http://127.0.0.1/metadata/",
            "-db-uri",
            "postgresql://postgres:secret@127.0.0.1:5433",
            "-csv",
            "targets1of2.csv",
            "-csv",
            "targets2of2.csv",
            "--skip-publish-targets",
        ]
        result = client.invoke(
            import_targets.import_targets, options, obj=test_context
        )
        assert result.exit_code == 0, result.output
        assert "Finished." in result.output
        assert "Not targets published" in result.output
        assert import_targets.is_logged.calls == [
            pretend.call("fake-server", "test-token")
        ]
        import_targets.request_server.calls == [
            pretend.call(
                "fake-server",
                import_targets.URL.bootstrap.value,
                import_targets.Methods.get,
                headers="headers",
            )
        ]
        assert import_targets.get_headers.calls == [
            pretend.call(test_context["settings"])
        ]
        assert fake_response.json.calls == [pretend.call()]
        assert import_targets.create_engine.calls == [
            pretend.call("postgresql://postgres:secret@127.0.0.1:5433")
        ]
        assert import_targets._check_csv_files.calls == [
            pretend.call(csv_files=("targets1of2.csv", "targets2of2.csv"))
        ]
        assert import_targets.publish_targets.calls == []
        assert import_targets.task_status.calls == []
