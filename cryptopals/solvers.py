from cryptopals.conversions import (
    hex_to_ascii,
)
from functools import (
        partial,
)
from textwrap import (
        wrap,
)
from yaml import (
        safe_load,
)

LETTER_FREQUENCY = safe_load(
        open('cryptopals/data/letter_frequency.yaml', 'r'),
)


def score_letters(string):
    '''
    Score a string for english letters

    :param string: input string to score
    :return: an arbitrary score for number of english letters
    '''

    return sum(map(
        lambda c: LETTER_FREQUENCY.get(c.upper(), 0),
        string,
    ))


def find_best_plaintext(
        candidates,
):
    '''
    Given a list of candidate plaintext strings, find the most likely solution

    :param candidates: a list of candidate plaintext strings
    :param letters_only: only validate letters
    :return: the most likely solution
    '''

    # Return the most highly scored
    return max(
            candidates,
            key=lambda x: score_letters(x),
    )


def solve_single_byte_xor(ciphertext):
    '''
    Solve a single-byte XOR cipher

    :param ciphertext: ciphertext to decrypt:
    :return: most likely result
    '''

    # Generate a list of all possible plaintexts
    return find_best_plaintext(map(
            lambda x: list(map(
                lambda c: (c ^ x).to_bytes(1, 'little'),
                ciphertext,
            )),
            range(256),
    ))


def detect_single_byte_xor(list_of_ciphertexts):
    '''
    Detect which ciphertext is single-byte encrypted

    :param list_of_ciphertexts: a list of possible encrypted strings
    :return: most likely result
    '''

    # Find the single_byte_xor solution for each string
    return find_best_plaintext(map(
            solve_single_byte_xor,
            map(
                hex_to_ascii,
                list_of_ciphertexts,
            ),
    ))


def hamming_distance(
        first_string,
        second_string,
):
    '''
    Find the hamming distance of two strings

    :param first_string: the first string for hamming distance
    :param second_string: the second string for hamming distance
    :return: the hamming distance of the two strings
    '''

    return sum(map(
        lambda a, b: bin(a ^ b).count('1'),
        first_string,
        second_string,
    ))


def normalized_hamming_distance(
        ciphertext,
        key_size,
):
    '''
    Calculate the average normalized hamming distance of a ciphertext for a
    given key size

    :param ciphertext: the ciphertext to calculate
    :param key_size: the key size to test
    :return: the normalized hamming distance for the given key size
    '''

    # Calculate the average hamming distance of all adjacent blocks for given
    # key size
    return sum(map(
        lambda x: hamming_distance(
            ciphertext[:x * key_size],
            ciphertext[x * key_size: (x+1) * key_size],
        ) / key_size,
        range(1, int(len(ciphertext) / key_size)),
    )) / (int(len(ciphertext) / key_size) - 1)


def find_key_size(
        ciphertext,
        MIN_KEY_SIZE=2,
        MAX_KEY_SIZE=40,
):
    '''
    Find the most likely key size for a repeated key XOR

    :param ciphertext: the ciphertext to break
    :return: the most likely key size used to encrypt that ciphertext
    '''

    return min(
            range(MIN_KEY_SIZE, MAX_KEY_SIZE + 1),
            key=lambda x: normalized_hamming_distance(
                ciphertext,
                x,
            ),
    )


def split_by_key_size(
        ciphertext,
        key_size,
):
    '''
    Split a string into chunks based on key size

    :param ciphertext: The ciphertext to chop up
    :param key_size: the number of chunks to chop ciphertext into
    :return: a list of chunks representing ciphertext
    '''

    return list(map(
        lambda x: ciphertext[x::key_size],
        range(key_size),
    ))


def combine_by_key_size(
        chunks,
):
    '''
    Recombine chunks into plaintext based on key size

    :param chunks: The chunks to recombine
    :return: The estimated plaintext
    '''

    return map(
            lambda x: b''.join(x),
            zip(*chunks),
    )


def solve_repeated_key_xor(ciphertext):
    '''
    Find the plaintext of a repeated key XOR ciphertext

    :param ciphertext: the ciphertext to break
    :return: the corresponding plaintext
    '''

    # Determine the key size of the repeating key
    key_size = find_key_size(ciphertext)

    # Split up the ciphertext by key_size
    chunks = split_by_key_size(
            ciphertext,
            key_size,
    )

    # solve single byte xor for each chunk
    best_chunks = map(
            solve_single_byte_xor,
            chunks,
    )

    # Recombine best chunks
    return combine_by_key_size(
            best_chunks,
    )


def detect_aes_ecb(
        list_of_ciphertexts,
        block_size=16,
):
    '''
    Detect which ciphertext has been encrypted with aes_ecb

    :param list_of_ciphertexts: a list of hex encoded ciphertexts
    :param block_size: size in bytes of each block (default 16)
    :return: the most likely ciphertext encrypted with ecb
    '''

    return min(
            list_of_ciphertexts.split(b'\n'),
            key=lambda x: len(set(wrap(x.decode('utf-8'), block_size * 2))) -
            len(x) /
            (block_size * 2),
    )
