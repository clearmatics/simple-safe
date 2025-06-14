import json
from itertools import chain
from typing import Any, NamedTuple, Optional, Sequence

from eth_typing import ABI
from eth_typing.abi import ABIConstructor, ABIFunction, ABIFunctionType
from eth_utils.abi import (
    abi_to_signature,
    filter_abi_by_type,
    function_signature_to_4byte_selector,
    get_abi_input_names,
    get_aligned_abi_inputs,
    get_all_function_abis,
)
from eth_utils.address import to_checksum_address
from hexbytes import HexBytes
from web3._utils.abi import is_array_type


class Function(NamedTuple):
    name: str
    abi: ABIFunctionType
    sig: str
    selector: HexBytes


def find_function(
    abi: ABI, fn_identifier: str
) -> tuple[Optional[Function], Sequence[Function]]:
    """Find a function by an identifier in the Contract ABI."""
    exact_name_matches: list[Function] = []
    partial_name_matches: list[Function] = []
    for fn_abi in chain(
        filter_abi_by_type("fallback", abi), get_all_function_abis(abi)
    ):
        signature = abi_to_signature(fn_abi)
        selector = HexBytes(function_signature_to_4byte_selector(signature))
        name = fn_abi["name"] if fn_abi["type"] != "fallback" else "fallback"
        match = Function(
            name=name,
            abi=fn_abi,
            sig=signature,
            selector=selector,
        )
        if fn_identifier == selector.to_0x_hex() or fn_identifier == signature:
            return (match, [])
        elif fn_identifier.split("(")[0] == name and signature.startswith(
            fn_identifier
        ):
            exact_name_matches.append(match)
        elif signature.lower().startswith(fn_identifier.lower()):
            partial_name_matches.append(match)
    if len(exact_name_matches) == 1:
        return (exact_name_matches[0], [])
    return (
        None,
        sorted(chain(exact_name_matches, partial_name_matches), key=lambda fn: fn.sig),
    )


def parse_args(
    fn_abi: ABIFunction | ABIConstructor, str_args: Sequence[str]
) -> tuple[Any, ...]:
    """Parse a sequence of web3.py pytypes for an ABIElement input."""
    arg_names = map(str, get_abi_input_names(fn_abi))
    abi_types = [input["type"] for input in fn_abi.get("inputs", [])]
    if len(abi_types) != len(str_args):
        raise ValueError("Number of ABI inputs and arguments do not match.")
    args: list[Any] = []
    for i, (arg_name, abi_type, str_arg) in enumerate(
        zip(arg_names, abi_types, str_args)
    ):
        try:
            arg = parse_abi_type(abi_type, str_arg)
        except Exception as exc:
            raise Exception(
                f"{exc.__class__.__name__}: {exc} [argument: index={i} name={arg_name} type={abi_type} value='{str_arg}']"
            ) from exc
        args.append(arg)
    return get_aligned_abi_inputs(fn_abi, tuple(args))[1]


def parse_abi_type(abi_type: str, val_str: str) -> Any:
    """Parse a web3.py pytype corresponding to an ABI type.

    The `abi_type` is the value of the "type" field in an ABI function's
    `inputs` list. Note this is not the same as in the normalized function name,
    as obtained from `get_abi_input_types()` for example.

    Additionally, note that:
    - enum values have the abi_type "uint8"
    - struct values have the abi_type "tuple"
    - fixed/ufixed types are omitted because they aren't assignable

    Reference: <https://docs.soliditylang.org/en/stable/abi-spec.html#types>
    """
    if abi_type.startswith("uint") or abi_type.startswith("int"):
        return int(val_str)
    elif abi_type == "address":
        return to_checksum_address(val_str)
    elif abi_type == "bool":
        if val_str not in ("true", "false"):
            raise ValueError(
                f"Boolean value  must be 'true' or 'false' (not '{val_str}'"
            )
        return True if val_str == "true" else False
    elif abi_type.startswith("bytes") or abi_type in ("string", "function"):
        return HexBytes(val_str)
    elif abi_type == "tuple" or is_array_type(abi_type):
        val: list[Any] | dict[str, Any] = json.loads(val_str)
        if isinstance(val, list):
            return tuple(val)
        return val
    else:
        raise NotImplementedError(f"Unknown ABI Type '{abi_type}'")
