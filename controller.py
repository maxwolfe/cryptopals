from libs.tools import (
        conversions,
)


def hex_to_base64(hex_str):
    '''
    Convert a hex string to a base64 encoded string

    :param hex_str: a hex string
    :return: a base64 encoded string
    '''

    try:
        return conversions.hex_to_base64(
                hex_str,
        ), 200
    except ValueError:
        return 'Failure', 400


def fixed_xor(
        first_hex,
        second_hex,
):
    '''
    XOR two hex strings

    :param first_hex: the first hex string to XOR
    :param second_hex: the second hex string to XOR

    :return: the hex of the XOR result
    '''

    try:
        first_int = int(first_hex, 16)
    except ValueError:
        return 'Failure', 400

    try:
        second_int = int(second_hex, 16)
    except ValueError:
        return 'Failure', 401

    return hex(first_int ^ second_int)[2:], 200
