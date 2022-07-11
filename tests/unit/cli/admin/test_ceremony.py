import pretend  # type: ignore
from securesystemslib.keys import generate_ed25519_key  # type: ignore

from kaprien.cli.admin.ceremony import ceremony  # type: ignore


class TestCeremonyGroupCLI:
    def test_ceremony(self, client):
        test_result = client.invoke(ceremony)
        assert test_result.exit_code == 1
        assert "Metadata Initialization Ceremony" in test_result.output

    def test_ceremony_start_no(self, client):
        test_result = client.invoke(ceremony, input="n\n")
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_not_ready_load_the_keys(self, client):
        input_step1 = [
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = ["n"]
        test_result = client.invoke(
            ceremony, input="\n".join(input_step1 + input_step2)
        )
        assert "Ceremony aborted." in test_result.output
        assert test_result.exit_code == 1

    def test_ceremony_start_default_values(self, client, monkeypatch):
        input_step1 = [
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = [
            "Y",
            "tests/files/JimiHendrix.key",
            "strongPass",
            "tests/files/JanisJoplin.key",
            "strongPass",
            "tests/files/ChrisCornel.key",
            "strongPass",
            "tests/files/KurtCobain.key",
            "strongPass",
            "tests/files/snapshot1.key",
            "strongPass",
            "tests/files/timestamp1.key",
            "strongPass",
            "tests/files/JoeCocker.key",
            "strongPass",
            "tests/files/bins1.key",
            "strongPass",
            "y",
            "y",
            "y",
            "y",
            "y",
            "y",
        ]

        class FakeKey:
            def __init__(self):
                self.error = None
                self.key = generate_ed25519_key()

        fake__load_key = pretend.call_recorder(lambda *a, **kw: FakeKey())
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._load_key", fake__load_key
        )

        test_result = client.invoke(
            ceremony, input="\n".join(input_step1 + input_step2)
        )
        assert test_result.exit_code == 0
        assert "Role: root" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "Threshold: 1" in test_result.output
        assert "Keys Type: offline" in test_result.output
        assert "JimiHendrix.key" in test_result.output
        assert "Role: targets" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "JanisJoplin.key" in test_result.output
        assert "ChrisCornel.key" in test_result.output
        assert "Role: snapshot" in test_result.output
        assert "Keys Type: online" in test_result.output
        assert "Role: timestamp" in test_result.output
        assert "KurtCobain.key" in test_result.output
        assert "JoeCocker.key" in test_result.output
        assert "bins1.key" in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output

    def test_ceremony_start_default_values_reconfigure_one_role(
        self, client, monkeypatch
    ):
        input_step1 = [
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        input_step2 = [
            "Y",
            "tests/files/JimiHendrix.key",
            "strongPass",
            "tests/files/JanisJoplin.key",
            "strongPass",
            "tests/files/ChrisCornel.key",
            "strongPass",
            "tests/files/KurtCobain.key",
            "strongPass",
            "tests/files/snapshot1.key",
            "strongPass",
            "tests/files/timestamp1.key",
            "strongPass",
            "tests/files/JoeCocker.key",
            "strongPass",
            "tests/files/bins1.key",
            "strongPass",
            "y",
            "y",
            "n",
            "",
            "",
            "",
            "tests/files/snapshot1.key",
            "strongPass",
            "y",
            "y",
            "y",
            "y",
        ]

        class FakeKey:
            def __init__(self):
                self.error = None
                self.key = generate_ed25519_key()

        fake__load_key = pretend.call_recorder(lambda *a, **kw: FakeKey())
        monkeypatch.setattr(
            "kaprien.cli.admin.ceremony._load_key", fake__load_key
        )

        test_result = client.invoke(
            ceremony, input="\n".join(input_step1 + input_step2)
        )
        assert test_result.exit_code == 0
        assert "Role: root" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "Threshold: 1" in test_result.output
        assert "Keys Type: offline" in test_result.output
        assert "JimiHendrix.key" in test_result.output
        assert "Role: targets" in test_result.output
        assert "Number of Keys: 1" in test_result.output
        assert "JanisJoplin.key" in test_result.output
        assert "ChrisCornel.key" in test_result.output
        assert "Role: snapshot" in test_result.output
        assert "Keys Type: online" in test_result.output
        assert "Role: timestamp" in test_result.output
        assert "KurtCobain.key" in test_result.output
        assert "JoeCocker.key" in test_result.output
        assert "bins1.key" in test_result.output
        # passwords not shown in output
        assert "strongPass" not in test_result.output
