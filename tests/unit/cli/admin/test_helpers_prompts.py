import click
import pretend
import pytest

from repository_service_tuf.cli.admin import helpers

class TestHelpersPrompts:
    def test_get_secret(self, monkeypatch):
        # Test for lines 268-276
        monkeypatch.setattr(click, "prompt", pretend.call_recorder(lambda msg, hide_input: "mysecret"))
        result = helpers._get_secret("my_secret_name")
        assert result == "mysecret"
        assert click.prompt.calls == [
            pretend.call(
                "\nEnter my_secret_name to sign (provide touch/bio authentication if needed)",
                hide_input=True
            )
        ]

    def test_prompt_key(self, monkeypatch):
        # Test for lines 285-288
        import prompt_toolkit
        mock_prompt = pretend.call_recorder(lambda msg, completer: "my/path")
        monkeypatch.setattr(prompt_toolkit, "prompt", mock_prompt)
        
        result = helpers._prompt_key("Message")
        assert result == "my/path"
        assert mock_prompt.calls[0].args[0] == "Message"

    def test_prompt_private_key(self, monkeypatch):
        # Test for lines 294-299
        mock_prompt_key = pretend.call_recorder(lambda msg: "private/path")
        monkeypatch.setattr(helpers, "_prompt_key", mock_prompt_key)
        
        result = helpers._prompt_private_key("my_key")
        assert result == "private/path"
        
    def test_load_signer_from_file_prompt_typeerror(self, monkeypatch):
        # Test for lines 323-324
        # We need to mock _prompt_private_key, open, click.prompt, load_pem_private_key
        mock_prompt_private = pretend.call_recorder(lambda name: "private/path")
        monkeypatch.setattr(helpers, "_prompt_private_key", mock_prompt_private)
        
        # mock open
        from unittest.mock import mock_open
        m = mock_open(read_data=b"dummy")
        monkeypatch.setattr("builtins.open", m)
        
        monkeypatch.setattr(click, "prompt", pretend.call_recorder(lambda *a, **kw: "password"))
        
        # simulate type error on first call, success on second
        call_count = [0]
        def mock_load(*a, **kw):
            if call_count[0] == 0:
                call_count[0] += 1
                raise TypeError("Bad password")
            return "private_key_obj"
            
        monkeypatch.setattr(helpers, "load_pem_private_key", mock_load)
        monkeypatch.setattr(helpers, "CryptoSigner", pretend.call_recorder(lambda priv, pub: "signer_obj"))
        
        mock_console = pretend.stub(print=pretend.call_recorder(lambda msg: None))
        monkeypatch.setattr(helpers, "console", mock_console)
        
        mock_public_key = pretend.stub(unrecognized_fields={}, keyid="1234567")
        result = helpers._load_signer_from_file_prompt(mock_public_key)
        
        assert result == "signer_obj"
        assert mock_console.print.calls == [pretend.call("Cannot load key: Bad password")]
