import json
from itertools import product

import pytest
from eth_account.account import Account
from eth_utils.abi import abi_to_signature, function_signature_to_4byte_selector
from hexbytes import HexBytes
from safe_eth.eth.constants import NULL_ADDRESS

from simple_safe.abi import find_function, parse_abi_type, parse_args


def test_find_function():
    foo = """
    {
      "type": "function",
      "name": "foo",
      "inputs": [],
      "outputs": [],
      "stateMutability": "nonpayable"
    }
    """
    foobar1 = """
    {
      "type": "function",
      "name": "foobar",
      "inputs": [],
      "outputs": [],
      "stateMutability": "nonpayable"
    }
    """
    foobar2 = """
    {
      "type": "function",
      "name": "foobar",
      "inputs": [
        {
          "name": "a",
          "type": "uint256",
          "internalType": "uint256"
        }
      ],
      "outputs": [],
      "stateMutability": "nonpayable"
    }
    """

    contract_abi = [json.loads(fn) for fn in (foo, foobar1, foobar2)]
    signatures = [abi_to_signature(fn_abi) for fn_abi in contract_abi]
    selectors = [
        HexBytes(function_signature_to_4byte_selector(signature))
        for signature in signatures
    ]

    for selector in selectors:
        exact, partial = find_function(contract_abi, selector.to_0x_hex())
        assert exact is not None
        assert exact.selector == selector
        assert len(partial) == 0

    exact, partial = find_function(contract_abi, "x")
    assert exact is None
    assert len(partial) == 0

    for identifier in ("", "f", "fo"):
        exact, partial = find_function(contract_abi, identifier)
        assert exact is None
        assert len(partial) == 3

    exact, partial = find_function(contract_abi, "foo")
    assert exact is not None
    assert exact.name == "foo"
    assert len(partial) == 0

    for identifier in ("foob", "foobar", "foobar("):
        exact, partial = find_function(contract_abi, identifier)
        assert exact is None
        assert len(partial) == 2

    exact, partial = find_function(contract_abi, "foobar(u")
    assert exact is not None
    assert exact.sig == "foobar(uint256)"
    assert len(partial) == 0


def test_parse_args_struct_values():
    fn_abi_str = """
    {
      "type": "function",
      "name": "funcName",
      "inputs": [
        {
          "name": "arg1",
          "type": "tuple",
          "internalType": "struct S",
          "components": [
            {
              "name": "x",
              "type": "uint256",
              "internalType": "uint256"
            },
            {
              "name": "y",
              "type": "uint256",
              "internalType": "uint256"
            },
            {
              "name": "z",
              "type": "uint256",
              "internalType": "uint256"
            }
          ]
        }
      ],
      "outputs": [],
      "stateMutability": "nonpayable"
    }
    """
    fn_abi = json.loads(fn_abi_str)
    for args in (
        ['{"x": 1, "y": 2, "z": 3}'],
        ['{"y": 2, "z": 3, "x": 1}'],
        ["[1, 2, 3]"],
    ):
        assert parse_args(fn_abi, args) == ((1, 2, 3),)


def test_parse_abi_type_abi_int():
    for abi_type, val_str in product(("int", "uint"), ("-1", "0", "1")):
        res = parse_abi_type(abi_type, val_str)
        assert isinstance(res, int)


def test_parse_abi_type_address():
    assert parse_abi_type("address", NULL_ADDRESS) == NULL_ADDRESS
    with pytest.raises(ValueError):
        parse_abi_type("address", "")
    for _ in range(3):
        address = Account.create().address
        res = parse_abi_type("address", address.lower())
        assert isinstance(res, str)
        assert res == address


def test_parse_abi_type_bool():
    with pytest.raises(ValueError):
        parse_abi_type("bool", "")
    for val_str in ["0", "False", "no"]:
        with pytest.raises(ValueError):
            parse_abi_type("bool", val_str)
    for val_str in ["1", "True", "yes"]:
        with pytest.raises(ValueError):
            parse_abi_type("bool", val_str)
    assert parse_abi_type("bool", "true")
    assert not parse_abi_type("bool", "false")


def test_parse_abi_type_invalid_value():
    for basic_typ in ("int", "address", "bool", "bytes", "tuple"):
        for typ in (basic_typ, basic_typ + "[]"):
            for val in (None, object, object()):
                with pytest.raises((ValueError, TypeError)):
                    parse_abi_type(typ, val)  # pyright: ignore[reportArgumentType]
