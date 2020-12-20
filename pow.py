import hashlib
import logging
import sys
from typing import Tuple


"""
Write a simple CLI script, that when given a 64-byte string, it finds a suitable 4-byte prefix so that, a
SHA256 hash of the prefix combined with the original string of bytes, has two last bytes as 0xca, 0xfe.
Script should expect the original string to be passed in hexadecimal format and should return two
lines, first being the SHA256 string found and second 4-byte prefix used (in hexadecimal format).
"""


logger = logging.getLogger(__name__)


def proof_of_work(
    input_hex: str,
    nonce_bytes=4,
    difficulty_pattern='cafe',
) -> Tuple[str, str]:
    """
    - Validates input hexadecimal string
    - Iterates over nonce bytes
    - Calculates prefix from nonce in each iteration
    - Calculates sha256 from sum of nonce and input string
    - Validates if difficulty pattern is matched
    """

    _validate_input_hex(input_hex)

    for i in range(_calculate_limit(nonce_bytes)):
        nonce = _get_nonce_in_hex(i, nonce_bytes)
        input_bytes = bytes.fromhex(f'{nonce}{input_hex}')
        sha256_bytes = hashlib.sha256(input_bytes).digest()
        sha256_hex = sha256_bytes.hex()
        if sha256_hex.endswith(difficulty_pattern):
            return sha256_hex, nonce

    raise ValueError(
        f'For following input: {input_hex} with {nonce_bytes} nonce bytes it was impossible '
        f'to solve proof of work to match ending with difficulty pattern: {difficulty_pattern}'
    )


def _calculate_limit(nonce_bytes: int) -> int:
    """
    Example:
        - nonce bytes: 4

        -> integer 4294967296
    """
    return int(nonce_bytes * 'ff', base=16) + 1


def _get_nonce_in_hex(nonce: int, nonce_bytes: int) -> str:
    """
    Example:
        - nonce: 255
        - nonce bytes: 2

        -> string '00ff'
    """
    return hex(nonce)[2:].zfill(nonce_bytes * 2)


def _validate_input_hex(input_hex: str):
    """
    Validates:
    - if input is in hex
    - if 0x prefix is absent
    - if input is 64 bytes long
    """
    try:
        int(input_hex, base=16)
    except ValueError:
        logger.error('Input string is not in a hexadecimal format!')
        raise

    assert not input_hex.startswith('0x'), 'Input string should not contain 0x prefix!'
    assert len(input_hex) == 128, 'Input string should be 64 bytes long!'


if __name__ == '__main__':
    """
    Steps:
    - Takes input string from passed argument
    - Fallbacks to sample hex string if no argument
    - Runs proof of work for following input
    - Prints found sha256 and valid nonce
    """
    if len(sys.argv) == 2:
        hex_string = sys.argv[1]
    else:
        hex_string = (
            '129df964b701d0b8e72fe7224cc71643'
            'cf8e000d122e72f742747708f5e3bb62'
            '94c619604e52dcd8f5446da7e9ff7459'
            'd1d3cefbcc231dd4c02730a22af9880c'
        )

    sha256_hex, nonce = proof_of_work(input_hex=hex_string)
    print(f'{sha256_hex}\n{nonce}')
