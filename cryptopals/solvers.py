from cryptopals.conversions import (
    hex_to_ascii,
)
from enchant import (
        Dict,
)

dictionary = Dict('en_US')


def score_string(string):
    '''
    Score a string for english words

    :param string: input string to score
    :return: an arbitrary score for number of english words
    '''

    words = []

    # Remove words with invalid characters before check
    for word in string.split(' '):
        for c in word:
            if c < 'A' or (c > 'Z' and c < 'a') or c > 'z':
                break
        else:
            if word:
                words.append(word)

    return sum(map(
        lambda x: 1 if dictionary.check(x) else 0,
        words,
    ))


def find_best_plaintext(candidates):
    '''
    Given a list of candidate plaintext strings, find the most likely solution

    :param candidates: a list of candidate plaintext strings
    :return: the most likely solution
    '''

    # Find score for all plaintexts (might need multiple later)
    scored_candidate = (
            (score_string(candidate), candidate) for candidate in candidates
    )

    # Return the most highly scored
    return sorted(
            scored_candidate,
            reverse=True,
    )[0][1]


def solve_single_byte_xor(hex_ciphertext):
    '''
    Solve a single-byte XOR cipher

    :param hex_ciphertext: hex string of ciphertext:
    :return: most likely result
    '''

    # Decode hex to byte representation
    initial_str = hex_to_ascii(
            hex_ciphertext,
            ret_bytes=True,
    )
    # Generate a list of all possible plaintexts
    candidates = map(
            lambda x: "".join([chr(char ^ x) for char in initial_str]),
            range(256),
    )

    return find_best_plaintext(candidates)


def detect_single_byte_xor(list_of_ciphertexts):
    '''
    Detect which ciphertext is single-byte encrypted

    :param list_of_ciphertexts: a list of possible encrypted strings
    :return: most likely result
    '''

    # Find the single_byte_xor solution for each string
    candidates = map(
            solve_single_byte_xor,
            list_of_ciphertexts,
    )

    return find_best_plaintext(candidates)
