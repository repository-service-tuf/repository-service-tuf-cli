import pytest
from rich.prompt import InvalidResponse

from repository_service_tuf.cli.admin.helpers import (
    SIGNERS,
    ROOT_SIGNERS,
    ONLINE_SIGNERS,
    SIGSTORE_ISSUERS,
    DELEGATIONS_TYPE,
    _Settings,
    Role,
    BinsRole,
    Roles,
    Settings,
    Metadatas,
    CeremonyPayload,
    UpdatePayload,
    SignPayload,
    _PositiveIntPrompt,
    _MoreThan1Prompt,
)


class TestHelpersExtra:
    def test_enums(self):
        assert SIGNERS.values() is not None
        assert SIGNERS.names() is not None

        assert ROOT_SIGNERS.HSM.value == "HSM"
        assert ROOT_SIGNERS.KEY_PEM.value == "Key PEM File"
        assert ROOT_SIGNERS.SIGSTORE.value == "Sigstore"

        assert ONLINE_SIGNERS.AWSKMS.value == "AWS KMS"
        assert ONLINE_SIGNERS.KEY_PEM.value == "Key PEM File"

        assert SIGSTORE_ISSUERS.GitHub.value == "https://github.com/login/oauth"
        
        assert DELEGATIONS_TYPE.BINS.value == "Bins (online key only)"
        assert "Bins (online key only)" in DELEGATIONS_TYPE.values()

    def test_dataclasses(self):
        settings = _Settings(
            timestamp_expiry=1,
            snapshot_expiry=1,
            targets_expiry=365,
            bins_expiry=1,
            bins_number=256,
        )
        assert settings.timestamp_expiry == 1
        assert settings.bins_number == 256

        role = Role(expiration=365)
        assert role.expiration == 365

        bins_role = BinsRole(expiration=1, number_of_delegated_bins=256)
        assert bins_role.number_of_delegated_bins == 256

        roles = Roles(
            root=role,
            timestamp=role,
            snapshot=role,
            targets=role,
        )
        assert roles.root.expiration == 365

        settings_obj = Settings(roles=roles)
        assert settings_obj.roles.root.expiration == 365

        metadatas = Metadatas(root={"some": "data"})
        assert metadatas.root == {"some": "data"}

        ceremony = CeremonyPayload(settings=settings_obj, metadata=metadatas)
        assert ceremony.timeout == 300
        assert ceremony.settings == settings_obj

        update = UpdatePayload(metadata=metadatas)
        assert update.metadata == metadatas

        sign = SignPayload(signature={"sig": "abc"})
        assert sign.signature == {"sig": "abc"}
        assert sign.role == "root"

    def test_positive_int_prompt(self):
        prompt = _PositiveIntPrompt("Enter a number")
        assert prompt.process_response("5") == 5
        
        with pytest.raises(InvalidResponse) as exc:
            prompt.process_response("0")
        assert "Please enter a valid positive integer number" in str(exc)
        
        with pytest.raises(InvalidResponse):
            prompt.process_response("-1")

    def test_more_than_1_prompt(self):
        prompt = _MoreThan1Prompt("Enter a threshold")
        assert prompt.process_response("2") == 2
        assert prompt.process_response("5") == 5
        
        with pytest.raises(InvalidResponse) as exc:
            prompt.process_response("1")
        assert "Please enter threshold above 1" in str(exc)
        
        with pytest.raises(InvalidResponse):
            prompt.process_response("0")
