# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import copy
import json

import pretend
from tuf.api.metadata import Root, Targets

import repository_service_tuf.cli.admin.metadata.stop_sign as stop_sign
from repository_service_tuf.helpers.api_client import URL
from tests.conftest import _HELPERS, _PAYLOADS, _PEMS, invoke_command


class TestStopSign:
    def test_stop_sign_root_sign_pending(
        self, monkeypatch, test_context, patch_getpass
    ):
        with open(f"{_PAYLOADS / 'sign_pending_roles.json'}") as f:
            full_data = json.load(f)

        stop_sign._get_pending_roles = pretend.call_recorder(
            lambda a: full_data["data"]["metadata"]
        )
        # selections interface. At least two options needed.
        select_options = iter(("root", None))
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: next(select_options),
        )

        stop_sign.send_payload = pretend.call_recorder(lambda **kw: "taskid")
        stop_sign.task_status = pretend.call_recorder(lambda *a: "OK")
        api_server = "http://127.0.0.1"
        test_context["settings"].SERVER = api_server

        inputs = [
            "y",  # Do you still want to stop signing process for root
        ]

        result = invoke_command(stop_sign.stop_sign, inputs, [], test_context)

        assert f"Signing process for {Root.type} deleted!\n" in result.stdout
        assert stop_sign._get_pending_roles.calls == [
            pretend.call(test_context["settings"])
        ]
        assert stop_sign.send_payload.calls == [
            pretend.call(
                settings=result.context["settings"],
                url=URL.METADATA_SIGN_DELETE.value,
                payload={"role": Root.type},
                expected_msg="Metadata sign delete accepted.",
                command_name="Metadata delete sign",
            )
        ]
        assert stop_sign.task_status.calls == [
            pretend.call(
                "taskid",
                result.context["settings"],
                "Stop Signing process status: ",
            )
        ]

    def test_stop_sign_targets_sign_pending(
        self, monkeypatch, test_context, patch_getpass
    ):
        trusted_targets_dict = {
            "signatures": [{"keyid": "keyid", "sig": "sig"}],
            "signed": {
                "_type": "targets",
                "spec_version": "1.0.0",
                "delegations": {
                    "keys": {
                        "2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241": {  # noqa: E501
                            "keytype": "rsa",
                            "scheme": "rsassa-pss-sha256",
                            "keyval": {
                                "public": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhX6rioiL/cX5Ys32InF\nU52H8tL14QeX0tacZdb+AwcH6nIh97h3RSHvGD7Xy6uaMRmGldAnSVYwJHqoJ5j2\nynVzU/RFpr+6n8Ps0QFg5GmlEqZboFjLbS0bsRQcXXnqJNsVLEPT3ULvu1rFRbWz\nAMFjNtNNk5W/u0GEzXn3D03jIdhD8IKAdrTRf0VMD9TRCXLdMmEU2vkf1NVUnOTb\n/dRX5QA8TtBylVnouZknbavQ0J/pPlHLfxUgsKzodwDlJmbPG9BWwXqQCmP0DgOG\nNIZ1X281MOBaGbkNVEuntNjCSaQxQjfALVVU5NAfal2cwMINtqaoc7Wa+TWvpFEI\nWwIDAQAB\n-----END PUBLIC KEY-----\n"  # noqa: E501
                            },
                            "x-rstuf-key-name": "JC",
                        },
                        "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc": {  # noqa: E501
                            "keytype": "ed25519",
                            "scheme": "ed25519",
                            "keyval": {
                                "public": "4f66dabebcf30628963786001984c0b75c175cdcf3bc4855933a2628f0cd0a0f"  # noqa: E501
                            },
                            "x-rstuf-key-name": "JH",
                        },
                    },
                    "roles": [
                        {
                            "name": "default",
                            "terminating": True,
                            "keyids": [],
                            "threshold": 1,
                            "x-rstuf-expire-policy": 1,
                            "paths": ["*"],
                        },
                        {
                            "name": "production",
                            "terminating": True,
                            "keyids": [
                                "2f685fa7546f1856b123223ab086b3def14c89d24eef18f49c32508c2f60e241",  # noqa: E501
                                "c6d8bf2e4f48b41ac2ce8eca21415ca8ef68c133b47fc33df03d4070a7e1e9cc",  # noqa: E501
                            ],
                            "threshold": 2,
                            "x-rstuf-expire-policy": 7,
                            "paths": ["production/*"],
                        },
                    ],
                },
                "expires": "2030-01-01T00:00:00Z",
                "targets": {
                    "file1.txt": {
                        "hashes": {
                            "sha256": "65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da"  # noqa: E501
                        },
                        "length": 31,
                    },
                    "dir/file2.txt": {
                        "hashes": {
                            "sha256": "452ce8308500d83ef44248d8e6062359211992fd837ea9e370e561efb1a4ca99"  # noqa: E501
                        },
                        "length": 39,
                    },
                },
                "version": 1,
            },
        }

        # Change new targets;
        new_targets_dict = copy.deepcopy(trusted_targets_dict)
        new_targets_dict["signed"]["version"] = 10
        pending_roles = {
            "trusted_targets": trusted_targets_dict,
            "targets": new_targets_dict,
        }

        stop_sign._get_pending_roles = pretend.call_recorder(
            lambda a: pending_roles
        )

        # selections interface. At least two options needed.
        select_options = iter(("targets", None))
        monkeypatch.setattr(
            f"{_HELPERS}._select",
            lambda *a: next(select_options),
        )
        stop_sign.send_payload = pretend.call_recorder(lambda **kw: "taskid")
        stop_sign.task_status = pretend.call_recorder(lambda *a: "OK")
        api_server = "http://127.0.0.1"
        test_context["settings"].SERVER = api_server

        inputs = [
            "y",  # Do you still want to stop signing process for root
        ]

        res = invoke_command(stop_sign.stop_sign, inputs, [], test_context)

        assert f"Signing process for {Targets.type} deleted!\n" in res.stdout
        assert stop_sign._get_pending_roles.calls == [
            pretend.call(test_context["settings"])
        ]
        assert stop_sign.send_payload.calls == [
            pretend.call(
                settings=res.context["settings"],
                url=URL.METADATA_SIGN_DELETE.value,
                payload={"role": Targets.type},
                expected_msg="Metadata sign delete accepted.",
                command_name="Metadata delete sign",
            )
        ]
        assert stop_sign.task_status.calls == [
            pretend.call(
                "taskid",
                res.context["settings"],
                "Stop Signing process status: ",
            )
        ]


class TestStopSignInvalidCases:
    def test_stop_sign_no_api_server_or_settings(
        self, monkeypatch, test_context, patch_getpass
    ):
        test_context["settings"].SERVER = None

        result = invoke_command(
            stop_sign.stop_sign, [], [], test_context, std_err_empty=False
        )
        err_prefix = "Needed '--api-server' admin option"
        err_suffix = "or 'SERVER' in RSTUF cofig"
        assert err_prefix in result.stderr
        assert err_suffix in result.stderr
