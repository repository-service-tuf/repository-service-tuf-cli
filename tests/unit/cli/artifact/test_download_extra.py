import json
import pytest
from unittest.mock import mock_open
from click import ClickException

import pretend
from repository_service_tuf.cli.artifact import download

class TestDownloadExtra:
    def test__check_root(self, monkeypatch):
        mock_metadata = pretend.stub(
            verify_delegate=pretend.call_recorder(lambda *a: None)
        )
        monkeypatch.setattr(download.Metadata, "from_dict", pretend.call_recorder(lambda d: mock_metadata))
        
        valid_json = b'{"signatures": [], "signed": {"_type": "root", "version": 1}}'
        download._check_root(valid_json)
        
        assert download.Metadata.from_dict.calls == [pretend.call(json.loads(valid_json.decode("utf-8")))]
        assert mock_metadata.verify_delegate.calls == [pretend.call(download.Root.type, mock_metadata)]

    def test__check_root_invalid(self, monkeypatch):
        with pytest.raises(ClickException, match="Invalid trusted root metadata"):
            download._check_root(b"not valid json")
            
    def test__load_root_from_file(self, monkeypatch):
        valid_json = b'{"mock": "data"}'
        monkeypatch.setitem(download.__builtins__, "open", mock_open(read_data=valid_json))
        
        monkeypatch.setattr(download, "_check_root", pretend.call_recorder(lambda r: None))
        
        res = download._load_root_from_file("fake_path")
        assert res == valid_json
        assert download._check_root.calls == [pretend.call(valid_json)]

    def test__load_root_from_url_read(self, monkeypatch):
        valid_json = b'{"mock": "url"}'
        mock_response = pretend.stub(
            read=pretend.call_recorder(lambda: valid_json),
            __enter__=lambda *a: mock_response,
            __exit__=lambda *a: None,
        )
        monkeypatch.setattr(download.request, "urlopen", pretend.call_recorder(lambda u: mock_response))
        monkeypatch.setattr(download, "_check_root", pretend.call_recorder(lambda r: None))
        
        res = download._load_root_from_url("http://example.com/root")
        assert res == valid_json
        assert download._check_root.calls == [pretend.call(valid_json)]
        assert download.request.urlopen.calls == [pretend.call("http://example.com/root")]

    def test__load_root_from_url_urlerror(self, monkeypatch):
        def raise_urlerror(u):
            raise download.error.URLError("mock error")
            
        monkeypatch.setattr(download.request, "urlopen", raise_urlerror)
        
        with pytest.raises(ClickException, match="Failed to download trusted root from http://example.com/root: mock error"):
            download._load_root_from_url("http://example.com/root")

    def test__load_trusted_root_file(self, monkeypatch):
        monkeypatch.setattr(download.os.path, "isfile", lambda f: True)
        monkeypatch.setattr(download, "_load_root_from_file", pretend.call_recorder(lambda f: b"data"))
        assert download._load_trusted_root("path") == b"data"
        assert download._load_root_from_file.calls == [pretend.call("path")]

    def test__load_trusted_root_url(self, monkeypatch):
        monkeypatch.setattr(download.os.path, "isfile", lambda f: False)
        monkeypatch.setattr(download, "_load_root_from_url", pretend.call_recorder(lambda u: b"data"))
        assert download._load_trusted_root("http://example.com") == b"data"
        assert download._load_root_from_url.calls == [pretend.call("http://example.com")]

    def test__load_trusted_root_json(self, monkeypatch):
        monkeypatch.setattr(download.os.path, "isfile", lambda f: False)
        monkeypatch.setattr(download, "_check_root", pretend.call_recorder(lambda d: None))
        
        res = download._load_trusted_root('{"fake": "json"}')
        assert res == b'{"fake": "json"}'
        assert download._check_root.calls == [pretend.call(b'{"fake": "json"}')]
