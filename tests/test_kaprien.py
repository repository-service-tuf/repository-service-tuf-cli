from kaprien.cli import kaprien


class TestKaprien:
    def test_kaprien(self, client):

        test_result = client.invoke(kaprien)
        assert test_result.exit_code == 0
