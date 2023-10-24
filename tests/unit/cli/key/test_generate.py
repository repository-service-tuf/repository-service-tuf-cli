# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import pretend
import pytest
from securesystemslib.exceptions import FormatError  # type: ignore

from repository_service_tuf.cli.key import generate
from repository_service_tuf.cli.key.generate import _verify_password
from repository_service_tuf.constants import KeyType
from repository_service_tuf.helpers import tuf


class TestGenerateInteraction:
    """Test the Key Generate Interaction"""

    @pytest.mark.parametrize("key_type", KeyType.get_all_members() + ["\n"])
    def test_generate_key_types(self, key_type: str, client) -> None:
        """
        Test that all `KeyType` enum members are possible input choices.

        Note: We also test that a default ('\n') key type value is set
        """

        test_result = client.invoke(
            generate.generate,
            input=key_type,  # Choose key type [ed25519/ecdsa/rsa] (ed25519)
        )

        assert (
            "Choose key type [ed25519/ecdsa/rsa] (ed25519):"
        ) in test_result.output

        assert (
            "Please select one of the available options"
            not in test_result.output
        )

        assert test_result.exit_code == 1

    @pytest.mark.parametrize("key_type", KeyType.get_all_members())
    def test_generate_types_generation(self, key_type, client) -> None:
        """
        Test that all `KeyType` enum members input choices call the appropriate
        keypair generate function
        """

        password = "test-password"
        filename = "test-filename"
        inputs = [
            key_type,  # Choose key type [ed25519/ecdsa/rsa] (ed25519)
            filename,  # Enter the keys' filename ...
            "y",  # Do you want to overwrite the existing 'test-filename' file?  # noqa: E501
        ]

        generate._verify_password = pretend.call_recorder(lambda a: password)
        generate.load_key = pretend.call_recorder(
            lambda *a: tuf.RSTUFKey(
                key={
                    "keyid": "keyid",
                    "keytype": "keytype",
                    "scheme": "scheme",
                    "keyval": {"public": "k_public", "private": "private"},
                }
            )
        )

        mock_file_path = "repository_service_tuf.cli.key.generate."
        mocked_functions = {
            "ed25519": "_generate_and_write_ed25519_keypair",
            "ecdsa": "_generate_and_write_ecdsa_keypair",
            "rsa": "_generate_and_write_rsa_keypair",
        }

        with patch(
            mock_file_path + mocked_functions[key_type],
            return_value=None,
        ) as mock_keypair:
            test_result = client.invoke(
                generate.generate,
                input="\n".join(inputs),
                catch_exceptions=False,
            )

            mock_keypair.called_once()
            assert test_result.exit_code == 0
            assert generate.load_key.calls == [
                pretend.call(filename, key_type, password, "")
            ]
            assert "keyid" in test_result.output
            assert "keytype" in test_result.output
            assert "scheme" in test_result.output
            assert "k_public" in test_result.output
            assert "k_private" not in test_result.output

    @pytest.mark.parametrize("filename", ["\n", "test-filename"])
    def test_generate(self, filename: str, client) -> None:
        """
        Test all the steps in the `generate` sub-command work as expected

        Note: We also test that a default ('\n') filename value is set
        """

        try:
            key_type = "rsa"
            password = "test-password"
            inputs = [
                key_type,  # Choose key type [ed25519/ecdsa/rsa] (ed25519)
                filename,  # Enter the keys' filename ...
                "y",  # Do you want to overwrite the existing 'filename' file
            ]

            generate._verify_password = pretend.call_recorder(
                lambda a: password
            )

            test_result = client.invoke(
                generate.generate,
                input="\n".join(inputs),
                catch_exceptions=False,
            )

            # the default option for the filename
            if filename == "\n":
                filepath = f"id_{key_type}"
            else:
                filepath = filename

            assert generate._verify_password.calls == [  # type: ignore
                pretend.call(filepath)
            ]

            # password not shown in output
            assert password not in test_result.output

            assert test_result.exit_code == 0

        finally:
            # remove the generated keys
            Path(filepath).unlink(missing_ok=True)
            Path(filepath + ".pub").unlink(missing_ok=True)

    def test_generate_file_overwrite(self, client) -> None:
        """Test the 'overwrite file' prompt"""

        key_type = "rsa"
        password = "test-password"
        filename = "test-filename"
        inputs = [
            key_type,  # Choose key type [ed25519/ecdsa/rsa] (ed25519)
            filename,  # Enter the keys' filename ...
            "n",  # Do you want to overwrite the existing 'test-filename' file?
        ]

        generate.os.path.isfile = pretend.call_recorder(lambda *a, **kw: True)

        generate._verify_password = pretend.call_recorder(lambda a: password)

        test_result = client.invoke(
            generate.generate,
            input="\n".join(inputs),
            catch_exceptions=False,
        )

        assert generate.os.path.isfile.calls == [pretend.call(filename)]  # type: ignore # noqa: E501

        # verify `_verify_password` is never called
        assert generate._verify_password.calls == []  # type: ignore

        assert (
            f"Do you want to overwrite the existing '{filename}' file?"
            in test_result.output
        )

        assert "Key creation aborted." in test_result.output

        # password not shown in output
        assert password not in test_result.output

        assert test_result.exit_code == 1


class TestGenerateFunctions:
    """Test the Key Generate Functions"""

    @mock.patch("repository_service_tuf.cli.key.generate.get_password")
    def test__verify_password(self, mock_password, capsys) -> None:
        """
        Test that the password is verified correctly
        """

        mock_password.return_value = "test-password"

        generate._verify_password("test-filename")

        captured = capsys.readouterr()

        assert (
            "encryption password must be 1 or more characters long\n"
            not in captured.out
        )

    @mock.patch("repository_service_tuf.cli.key.generate.get_password")
    def test__verify_password_empty_password(
        self, mock_password, capsys
    ) -> None:
        """
        Test that the password is verified correctly if it is empty at the
        first attempt
        """

        mock_password.side_effect = ["", "test-password"]

        _verify_password("test-filename")

        captured = capsys.readouterr()

        assert captured.out == (
            "encryption password must be 1 or more characters long\n"
        )

    @mock.patch("repository_service_tuf.cli.key.generate.get_password")
    def test__verify_password_not_string_password(self, mock_password) -> None:
        """
        Test that the password is verified correctly if it is a number at the
        first attempt
        """

        password = 123
        mock_password.side_effect = [password, "test-password"]

        with pytest.raises(FormatError):
            _verify_password("test-filename")
