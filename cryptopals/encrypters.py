def repeated_key_xor(
        byte_string,
        byte_key,
):
    '''
    Encrypted or decrypt a byte-string with a repeated key XOR

    :param byte_string: a binary string to encrypt or decrypt
    :param byte_key: a binary key to use for encryption/decryption
    '''

    xor_str = ''

    for idx, char in enumerate(byte_string):
        xor_str += chr(ord(char) ^ ord(byte_key[idx % len(byte_key)]))

    return xor_str
