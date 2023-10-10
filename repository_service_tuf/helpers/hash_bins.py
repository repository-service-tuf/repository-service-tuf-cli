# SPDX-FileCopyrightText: 2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import hashlib

NUMBER_OF_BINS = 32
PREFIX_LEN = len(f"{(NUMBER_OF_BINS - 1):x}")
NUMBER_OF_PREFIXES = 16**PREFIX_LEN
BIN_SIZE = NUMBER_OF_PREFIXES // NUMBER_OF_BINS


def _bin_name(low: int, high: int) -> str:
    """Generates a bin name according to the hash prefixes the bin serves.

    The name is either a single hash prefix for bin size 1, or a range of hash
    prefixes otherwise. The prefix length is needed to zero-left-pad the
    hex representation of the hash prefix for uniform bin name lengths.
    """
    if low == high:
        return f"{low:0{PREFIX_LEN}x}"

    return f"{low:0{PREFIX_LEN}x}-{high:0{PREFIX_LEN}x}"


def find_hash_bin(path: str) -> str:
    """Returns name of bin for artifact file"""
    """ based on the artifact path hash."""
    # Generate hash digest of passed artifact path and take its prefix,
    # given the global prefix length for the given number of bins.
    hasher = hashlib.sha256()
    hasher.update(path.encode("utf-8"))
    artifact_name_hash = hasher.hexdigest()
    prefix = int(artifact_name_hash[:PREFIX_LEN], 16)
    # Find lower and upper bounds for hash prefix given its numerical
    # value and the the general bin size for the given number of bins.
    low = prefix - (prefix % BIN_SIZE)
    high = low + BIN_SIZE - 1
    return _bin_name(low, high)
