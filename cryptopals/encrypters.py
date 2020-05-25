from Cryptodome.Cipher import (
        AES,
)
from itertools import (
        cycle,
)


def repeated_key_xor(
        byte_string,
        byte_key,
):
    '''
    Encrypted or decrypt a byte-string with a repeated key XOR

    :param byte_string: a binary string to encrypt or decrypt
    :param byte_key: a binary key to use for encryption/decryption
    '''

    return map(
            lambda c, k: (c ^ k).to_bytes(1, 'little'),
            byte_string,
            cycle(byte_key),
    )


def decrypt_aes_ecb(
        ciphertext,
        key,
):
    '''
    Decrypt AES-ECB with a known key

    :param ciphertext: the ciphertext to decrypt
    :param key: the secret key used for decryption
    :return: the desired plaintext
    '''

    return AES.new(
            key,
            AES.MODE_ECB,
    ).decrypt(ciphertext)
