from cryptopals import (
        conversions,
        encrypters,
        solvers,
)


def _sanitize_for_output(iterable):
    '''
    Sanitize an iterble input to send

    :param iterable: an unkown iterable to sanitize
    :return: an ascii string
    '''

    if isinstance(iterable, list) or isinstance(iterable, map):
        iterable = b''.join(iterable)

    if isinstance(iterable, bytes):
        iterable = iterable.decode('utf-8')

    return iterable


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
        return _sanitize_for_output(
                solvers.solve_single_byte_xor(
                    conversions.hex_to_ascii(
                        hex_ciphertext,
                    ),
                ),
        ), 200
    except ValueError:
        return 'Not a hex string', 400


def detect_single_byte_xor(ciphertext_file):
    '''
    Detect which ciphertext is single-byte encrypted

    :param ciphertext_file: a file contianing possible encrypted strings
    :return: the hidden plaintext
    '''

    # Convert byte file into list of strings
    list_of_ciphertexts = map(
            lambda x: x.decode('utf-8'),
            ciphertext_file.read().split(b'\n')
    )

    try:
        return _sanitize_for_output(
                solvers.detect_single_byte_xor(list_of_ciphertexts),
        ), 200
    except ValueError:
        return 'An entry is not a hex string', 400


def repeated_key_xor(
        plaintext,
        key,
):
    '''
    Encrypt plaintext with repeating key XOR cipher

    :param plaintext: the text to encrypt
    :param key: the key to use in encryption
    :return: the corresponding ciphertext
    '''

    if not key:
        return 'Invalid key', 400

    return conversions.ascii_to_hex(
            b''.join(encrypters.repeated_key_xor(
                plaintext,
                key,
            )),
    ), 200


def solve_repeated_key_xor(ciphertext_file):
    '''
    Find the plaintext for a repeated key encrypted ciphertext

    :param ciphertext_file: the ciphertext file encoded in base64
    :return: the hidden plaintext
    '''

    try:
        return _sanitize_for_output(
                solvers.solve_repeated_key_xor(
                    conversions.base64_to_ascii(
                        ciphertext_file.read(),
                    ),
                ),
        ), 200
    except ValueError:
        return 'The ciphertext is not a base64 string', 400


def decrypt_aes_ecb(
        ciphertext_file,
        ascii_key,
):
    '''
    Find the plaintext for an AES-ECB ciphertext

    :param ciphertext_file: a file with the base64 encoded ciphertext
    :param ascii_key: the ascii-encoded key
    :return: the desired plaintext
    '''

    try:
        return _sanitize_for_output(
                encrypters.decrypt_aes_ecb(
                    conversions.base64_to_ascii(
                        ciphertext_file.read(),
                    ),
                    ascii_key.encode('utf-8'),
                ),
        ), 200
    except ValueError:
        return 'The ciphertext or key are of incorrect size.', 400


def detect_aes_ecb(ciphertext_file):
    '''
    Find the ciphertext file which is encrypted by AES-ECB

    :param ciphertext_file: a file with a list of hex encoded ciphertext
    :return: the most likely ciphertext that is AES-ECB encrypted
    '''

    return _sanitize_for_output(
            solvers.detect_aes_ecb(
                ciphertext_file.read(),
            ),
    ), 200
