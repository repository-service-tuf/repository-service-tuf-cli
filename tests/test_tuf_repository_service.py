from tuf_repository_service.cli import trs


class TestTRSCLI:
    def test_tuf_repository_service(self, client):

        test_result = client.invoke(trs)
        assert test_result.exit_code == 0
