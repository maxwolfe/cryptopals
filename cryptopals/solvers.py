from cryptopals.conversions import (
    hex_to_ascii,
)
from textstat import (
        flesch_reading_ease as fre_score,
        smog_index as si_score,
        flesch_kincaid_grade as fkg_score,
        coleman_liau_index as cli_score,
        automated_readability_index as ari_score,
        dale_chall_readability_score as dcr_score,
        difficult_words as dw_score,
        linsear_write_formula as lwf_score,
        gunning_fog as gf_score,
        text_standard as ts_score,
)


def score_string(string):
    '''
    Score a string for readability

    :param string: input string to score
    :return: an arbitrary score for readability
    '''

    '''
    valuable_indexes = [
            fre_score,
            si_score,
            fkg_score,
            cli_score,
            ari_score,
            dcr_score,
            dw_score,
            lwf_score,
            gf_score,
            ts_score
    ]
    '''

    # Sanitize non-strings
    for char in string:
        if ord(char) < 0x20 or ord(char) > 0x7e:
            return 0

    # Use only fre score for now
    return fre_score(string)


def find_best_plaintext(candidates):
    '''
    Given a list of candidate plaintext strings, find the most likely solution

    :param candidates: a list of candidate plaintext strings
    :return: the most likely solution
    '''

    # Find score for all plaintexts (might need multiple later)
    scores = (score_string(candidate) for candidate in candidates)

    # Return the most highly scored
    return sorted(
            zip(candidates, scores),
            key=lambda x: x[1],
            reverse=True,
    )[0][0]


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
    candidates = list(map(
            lambda x: "".join([chr(char ^ x) for char in initial_str]),
            range(256),
    ))

    return find_best_plaintext(candidates)
