import json
from itertools import product
from typing import Any

import pytest
from eth_account.account import Account
from safe_eth.eth.constants import NULL_ADDRESS

from simple_safe.abi import find_function, parse_abi_type, parse_args


def test_find_function():
    f1 = """
    {
      "type": "function",
      "name": "f",
      "inputs": [],
      "outputs": [],
      "stateMutability": "nonpayable"
    }
    """
    f2 = """
    {
      "type": "function",
      "name": "f",
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
    f3 = """
    {
      "type": "function",
      "name": "f",
      "inputs": [
        {
          "name": "a",
          "type": "uint256",
          "internalType": "uint256"
        },
        {
          "name": "b",
          "type": "uint256",
          "internalType": "uint256"
        }
      ],
      "outputs": [],
      "stateMutability": "nonpayable"
    }
    """
    

    abi = [json.loads(f) for f in (f1, f2, f3)]
    funcs = find_function(abi, "f")

    assert len(find_function(abi, "x")) == 0

    for func in funcs:
        res = find_function(abi, func.selector.to_0x_hex())
        assert len(res)==1
        assert res[0].selector == func.selector

    abi: list[Any] = []
    for i, f in enumerate((f1, f2, f3)):
        abi.append(json.loads(f))
        assert len(find_function(abi, "f")) == i+1

    
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
