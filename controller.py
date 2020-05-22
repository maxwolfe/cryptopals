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
