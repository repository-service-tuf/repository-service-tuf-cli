#!/bin/python

# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from securesystemslib.interface import (  # type: ignore
    generate_and_write_ed25519_keypair,
)

generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/root1.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/root2.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/root3.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/targets1.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/targets2.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/snapshot1.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/timestamp1.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/bin1.key"
)
generate_and_write_ed25519_keypair(
    "strongPass", filepath="tests/files/bins1.key"
)
