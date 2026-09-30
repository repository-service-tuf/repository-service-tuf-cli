import json
import pytest
import click
import pretend

from repository_service_tuf.cli.admin.metadata import sign
from repository_service_tuf.helpers.api_client import URL

class TestSignTargetsExtra:
    def test_sign_targets_success(self, monkeypatch):
        # Mock pending_roles
        trusted_targets_dict = {
            "signatures": [],
            "signed": {
                "_type": "targets",
                "version": 1,
                "spec_version": "1.0.0",
                "expires": "2030-01-01T00:00:00Z",
                "targets": {},
                "delegations": {
                    "keys": {
                        "key-abc": {
                            "keytype": "ed25519",
                            "scheme": "ed25519",
                            "keyval": {"public": "public-key"}
                        }
                    },
                    "roles": [
                        {
                            "name": "my_role",
                            "keyids": ["key-abc"],
                            "threshold": 1,
                            "terminating": False,
                            "paths": ["*"]
                        }
                    ]
                }
            }
        }
        
        my_role_dict = {
            "signatures": {},
            "signed": {
                "_type": "targets",
                "version": 1,
                "spec_version": "1.0.0",
                "expires": "2030-01-01T00:00:00Z",
                "targets": {}
            }
        }

        pending_roles = {
            "my_role": my_role_dict,
            "trusted_targets": trusted_targets_dict
        }

        monkeypatch.setattr(sign, "_get_pending_roles", lambda *a: pending_roles)
        monkeypatch.setattr(sign, "_select_role", lambda *a: "my_role")
        monkeypatch.setattr(sign, "_print_targets", lambda *a: None)
        
        key_mock = pretend.stub()
        monkeypatch.setattr(sign, "_select_key", pretend.call_recorder(lambda keys: key_mock))
        
        mock_signature = pretend.stub(
            to_dict=lambda: {"sig": "mocked-sig", "keyid": "key-abc"}
        )
        monkeypatch.setattr(sign, "_add_signature_prompt", pretend.call_recorder(lambda md, key: mock_signature))
        
        # We need a context with settings
        settings_mock = pretend.stub(
            get=lambda k: "http://server",
            SERVER="http://server"
        )
        
        monkeypatch.setattr(sign, "send_payload", pretend.call_recorder(lambda **kw: "task123"))
        monkeypatch.setattr(sign, "task_status", pretend.call_recorder(lambda *a: None))
        
        @click.command()
        @click.pass_context
        def wrapper(ctx):
            ctx.obj = {"settings": settings_mock}
            ctx.invoke(sign.sign, dry_run=False, out=None, input=None)
            
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(wrapper)
        
        assert result.exit_code == 0
        assert "Metadata Signed and sent to the API! 🔑" in result.output
        assert sign.send_payload.calls == [
            pretend.call(
                settings=settings_mock,
                url=URL.METADATA_SIGN.value,
                payload={"signature": {"sig": "mocked-sig", "keyid": "key-abc"}, "role": "my_role"},
                expected_msg="Metadata sign accepted.",
                command_name="Metadata sign",
            )
        ]

    def test_sign_targets_no_delegations(self, monkeypatch):
        # Mock pending_roles
        trusted_targets_dict = {
            "signatures": [],
            "signed": {
                "_type": "targets",
                "version": 1,
                "spec_version": "1.0.0",
                "expires": "2030-01-01T00:00:00Z",
                "targets": {},
                # No delegations
            }
        }
        
        my_role_dict = {
            "signatures": {},
            "signed": {
                "_type": "targets",
                "version": 1,
                "spec_version": "1.0.0",
                "expires": "2030-01-01T00:00:00Z",
                "targets": {}
            }
        }

        pending_roles = {
            "my_role": my_role_dict,
            "trusted_targets": trusted_targets_dict
        }

        monkeypatch.setattr(sign, "_get_pending_roles", lambda *a: pending_roles)
        monkeypatch.setattr(sign, "_select_role", lambda *a: "my_role")
        monkeypatch.setattr(sign, "_print_targets", lambda *a: None)
        
        settings_mock = pretend.stub(
            get=lambda k: "http://server",
            SERVER="http://server"
        )
        
        @click.command()
        @click.pass_context
        def wrapper(ctx):
            ctx.obj = {"settings": settings_mock}
            ctx.invoke(sign.sign, dry_run=False, out=None, input=None)
            
        from click.testing import CliRunner
        runner = CliRunner()
        result = runner.invoke(wrapper)
        
        assert result.exit_code != 0
        assert "No custom delegations" in result.output



