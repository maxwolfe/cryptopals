import binascii

from base64 import (
        b64encode,
        b64decode,
)


def hex_to_ascii(
        hex_str,
):
    '''
    Convert a hex string into ascii representation

    :param hex_str: a hex string
    :return: an ascii string
    '''

    # Convert to string if bytes
    if isinstance(hex_str, bytes):
        hex_str = hex_str.decode('utf-8')

    return bytes.fromhex(
            hex_str,
    )


def ascii_to_hex(
        ascii_rep,
):
    '''
    Convert an ascii string into hex representation

    :param ascii_str: an ascii string
    :return: a hex encoded string
    '''

    # Convert to bytes if input is a string
    if isinstance(ascii_rep, str):
        ascii_rep = ascii_rep.encode('utf-8')

    return ascii_rep.hex()


def base64_to_ascii(
        base64_str,
):
    '''
    Convert a base64 string into ascii representation

    :param base64_str: a base64 encoded string
    :return: an ascii string
    '''

    # Convert to bytes if input is a string
    if isinstance(base64_str, str):
        base64_str = base64_str.encode('utf-8')

    return b64decode(base64_str)


def ascii_to_base64(
        ascii_rep,
):
    '''
    Convert an ascii string into base64 representation

    :param ascii_str: an ascii string
    :return: a base64 encoded string
    '''

    # Convert to bytes if input is a string
    if isinstance(ascii_rep, str):
        ascii_rep = ascii_rep.encode('utf-8')

    return b64encode(ascii_rep)


def hex_to_base64(
        hex_str,
):
    '''
    Convert a hex string to a base64 encoded string

    :param hex_str: a hex string
    :return: a base64 encoded string
    '''

    return ascii_to_base64(
            hex_to_ascii(
                hex_str,
            ),
    )
