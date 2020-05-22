import yaml

from controller import (
        hex_to_base64,
        fixed_xor,
        single_byte_xor,
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
