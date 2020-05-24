import controller
import yaml

from base64 import (
        b64decode,
)
from controller import (
        hex_to_base64,
        fixed_xor,
        single_byte_xor,
        detect_single_byte_xor,
        repeated_key_xor,
        solve_repeated_key_xor,
        decrypt_aes_ecb,
        detect_aes_ecb,
)
from mock import (
        Mock,
        patch,
)

IO_FILE = 'tests/io/io.yaml'
io = yaml.safe_load(open(IO_FILE, 'r'))


# Set 1 : Problem 1
def test_prob1_success():
    cur_problem = io['Set1']['Problem1']
    inputs = cur_problem['inputs']
    output = cur_problem['output']

    assert hex_to_base64(
            *inputs
    ) == (output, 200)


def test_prob1_fail_1():
    cur_problem = io['Set1']['Problem1']
    bad_input = 'Hello, World!'

    assert hex_to_base64(
            bad_input,
    )[1] == 400


# Set 1 : Problem 2
def test_prob2_success():
    cur_problem = io['Set1']['Problem2']
    inputs = cur_problem['inputs']
    output = cur_problem['output']

    assert fixed_xor(
            *inputs
    ) == (output, 200)


def test_prob2_fail_1():
    cur_problem = io['Set1']['Problem2']
    inputs = cur_problem['inputs']
    bad_input = 'Hello, World!'

    assert fixed_xor(
            bad_input,
            inputs[1],
    )[1] == 400


def test_prob2_fail_2():
    cur_problem = io['Set1']['Problem2']
    inputs = cur_problem['inputs']
    bad_input = 'Hello, World!'

    assert fixed_xor(
            inputs[0],
            bad_input,
    )[1] == 401


# Set 1 : Problem 3
def test_prob3_success():
    cur_problem = io['Set1']['Problem3']
    inputs = cur_problem['inputs']
    output = cur_problem['output']

    assert single_byte_xor(
            *inputs
    ) == (output, 200)


def test_prob3_fail_1():
    cur_problem = io['Set1']['Problem3']
    bad_input = 'Hello, World!'

    assert single_byte_xor(
            bad_input,
    )[1] == 400


# Set 1 : Problem 4
def test_prob4_success():
    cur_problem = io['Set1']['Problem4']
    inputs = open(cur_problem['inputs'][0], 'rb')
    output = cur_problem['output']

    assert detect_single_byte_xor(
            inputs,
    ) == (output, 200)


def test_prob4_fail_1():
    cur_problem = io['Set1']['Problem4']
    bad_input = Mock()
    bad_input.read.return_value = b'Hello, World\n'

    assert detect_single_byte_xor(
            bad_input,
    )[1] == 400


# Set 1 : Problem 5
def test_prob5_success():
    cur_problem = io['Set1']['Problem5']
    inputs = cur_problem['inputs']
    output = cur_problem['output']

    assert repeated_key_xor(
            *inputs
    ) == (output, 200)


def test_prob5_fail_1():
    cur_problem = io['Set1']['Problem5']
    inputs = cur_problem['inputs']
    bad_input = ""

    assert repeated_key_xor(
            inputs[0],
            bad_input,
    )[1] == 400


# Set 1 : Problem 6
def test_prob6_success():
    cur_problem = io['Set1']['Problem6']
    inputs = open(cur_problem['inputs'][0], 'rb')
    output = open(cur_problem['output'], 'r').read().strip('\n')

    assert solve_repeated_key_xor(
            inputs,
    ) == (output, 200)


# Set 1 : Problem 7
def test_prob7_success():
    cur_problem = io['Set1']['Problem7']
    input_file = open(cur_problem['inputs'][0], 'rb')
    input_key = cur_problem['inputs'][1]
    output = open(cur_problem['output'], 'r').read().strip('\n')

    assert decrypt_aes_ecb(
            input_file,
            input_key,
    ) == (output, 200)


# Set 1 : Problem 8
def test_prob8_success():
    cur_problem = io['Set1']['Problem8']
    inputs = open(cur_problem['inputs'][0], 'rb')
    output = open(cur_problem['output'], 'r').read().strip('\n')

    assert detect_aes_ecb(
            inputs,
    ) == (output, 200)
