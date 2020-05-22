from cryptopals import (
        conversions,
        solvers,
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
        return 'Not a hex string', 400


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
        return 'First input not a hex string', 400

    try:
        second_int = int(second_hex, 16)
    except ValueError:
        return 'Second input not a hex string', 401

    return hex(first_int ^ second_int)[2:], 200


def single_byte_xor(hex_ciphertext):
    '''
    Solve single byte XOR cipher

    :param hex_ciphertext: ciphertext as a hex string

    :return: the original plaintext
    '''

    try:
        return solvers.solve_single_byte_xor(hex_ciphertext), 200
    except ValueError:
        return "Not a hex string", 400
    except IndexError:
        return "No solutions found", 401
