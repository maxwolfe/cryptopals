import controller
import yaml

from base64 import (
        b64decode,
)
from mock import (
        Mock,
        patch,
)

INPUT_FILE_FORMAT = "tests/io/set{set_num}/set{set_num}_problem{prob_num}.in"
OUTPUT_FILE_FORMAT = "tests/io/set{set_num}/set{set_num}_problem{prob_num}.out"


def get_io_files(
        set_num,
        prob_num,
):
    return (
            open(
                INPUT_FILE_FORMAT.format(
                    set_num=set_num,
                    prob_num=prob_num,
                ),
                'rb',
            ),
            open(
                OUTPUT_FILE_FORMAT.format(
                    set_num=set_num,
                    prob_num=prob_num,
                ),
                'r',
            ),
    )


def test_prob1_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=1,
    )

    assert controller.hex_to_base64(
            inputs.read().decode('utf-8').strip('\n'),
    ) == (output.read().strip('\n'), 200)


def test_prob1_fail_1():
    bad_input = 'Hello, World!'

    assert controller.hex_to_base64(
            bad_input,
    )[1] == 400


# Set 1 : Problem 2
def test_prob2_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=2,
    )

    assert controller.fixed_xor(
            *inputs.read().decode('utf-8').strip('\n').split('\n')
    ) == (output.read().strip('\n'), 200)


def test_prob2_fail_1():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=2,
    )
    bad_input = 'Hello, World!'

    assert controller.fixed_xor(
            bad_input,
            inputs.read().decode('utf-8').strip('\n').split('\n')[1],
    )[1] == 400


def test_prob2_fail_2():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=2,
    )
    bad_input = 'Hello, World!'

    assert controller.fixed_xor(
            inputs.read().decode('utf-8').split('\n')[0],
            bad_input,
    )[1] == 401


# Set 1 : Problem 3
def test_prob3_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=3,
    )

    assert controller.single_byte_xor(
            inputs.read().decode('utf-8').strip('\n'),
    ) == (output.read().strip('\n'), 200)


def test_prob3_fail_1():
    bad_input = 'Hello, World!'

    assert controller.single_byte_xor(
            bad_input,
    )[1] == 400


# Set 1 : Problem 4
def test_prob4_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=4,
    )

    assert controller.detect_single_byte_xor(
            inputs,
    ) == (output.read(), 200)


def test_prob4_fail_1():
    bad_input = Mock()
    bad_input.read.return_value = b'Hello, World\n'

    assert controller.detect_single_byte_xor(
            bad_input,
    )[1] == 400


# Set 1 : Problem 5
def test_prob5_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=5,
    )
    key = b'ICE'

    assert controller.repeated_key_xor(
            inputs.read().strip(b'\n'),
            key,
    ) == (output.read().strip('\n'), 200)


def test_prob5_fail_1():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=5,
    )
    bad_input = ""

    assert controller.repeated_key_xor(
            inputs,
            bad_input,
    )[1] == 400


# Set 1 : Problem 6
def test_prob6_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=6,
    )

    assert controller.solve_repeated_key_xor(
            inputs,
    ) == (output.read().strip('\n'), 200)


# Set 1 : Problem 7
def test_prob7_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=7,
    )
    key = "YELLOW SUBMARINE"

    assert controller.decrypt_aes_ecb(
            inputs,
            key,
    ) == (output.read().strip('\n'), 200)


# Set 1 : Problem 8
def test_prob8_success():
    inputs, output = get_io_files(
            set_num=1,
            prob_num=8,
    )

    assert controller.detect_aes_ecb(
            inputs,
    ) == (output.read().strip('\n'), 200)
