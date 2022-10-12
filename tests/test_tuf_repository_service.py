from repository_service_tuf.cli import rstuf


class TestRSTUFCLI:
    def test_tuf_repository_service(self, client):

        test_result = client.invoke(rstuf)
        assert test_result.exit_code == 0
