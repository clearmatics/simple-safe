import dataclasses
import json
import logging
from contextlib import contextmanager
from decimal import Decimal, localcontext
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    NamedTuple,
    Optional,
    TextIO,
    cast,
)

from eth_abi.abi import encode as abi_encode
from eth_abi.packed import encode_packed
from eth_account.messages import (
    _hash_eip191_message,  # pyright: ignore[reportPrivateUsage]
    encode_typed_data,
)
from eth_typing import ChecksumAddress, HexStr
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak
from eth_utils.currency import denoms
from hexbytes import (
    HexBytes,
)
from web3.constants import ADDRESS_ZERO
from web3.types import Wei
from web3.utils.address import get_create2_address

from simple_safe.constants import SAFE_SETUP_FUNC_SELECTOR, SAFE_SETUP_FUNC_TYPES

from .chain import ChainData

if TYPE_CHECKING:
    from safe_eth.eth import EthereumClient
    from safe_eth.safe import SafeTx
    from safe_eth.safe.safe_signature import SafeSignature


@dataclasses.dataclass(kw_only=True)
class DeployParams:
    # deployment
    proxy_factory: ChecksumAddress
    singleton: ChecksumAddress
    chain_id: Optional[int]
    salt_nonce: int
    variant: "SafeVariant"
    # initialization
    owners: list[ChecksumAddress]
    threshold: int
    fallback: ChecksumAddress


class SafeVariant(Enum):
    SAFE = 1
    SAFE_L2 = 2
    UNKNOWN = 3


class SafeTxData(NamedTuple):
    safetx: "SafeTx"
    data: dict[str, Any]
    preimage: HexBytes
    hash: HexBytes


class SignatureData(NamedTuple):
    sigbytes: HexBytes
    path: str
    valid: bool
    is_owner: bool
    # Invalid signature may not have these fields.
    sig: Optional["SafeSignature"]
    sigtype: Optional[str]
    address: Optional[ChecksumAddress]


def as_checksum(checksum_str: str) -> ChecksumAddress:
    """Cast to satisfy type checker."""
    return cast(ChecksumAddress, checksum_str)


def compute_safe_address(
    *,
    chain_id: Optional[int],
    fallback: ChecksumAddress,
    owners: list[ChecksumAddress],
    proxy_factory: ChecksumAddress,
    salt_nonce: int,
    singleton: ChecksumAddress,
    threshold: int,
) -> tuple[HexBytes, ChecksumAddress]:
    """Compute Safe address via SafeProxyFactory v1.4.1."""
    initializer_args = abi_encode(
        SAFE_SETUP_FUNC_TYPES,
        (
            owners,
            threshold,
            ADDRESS_ZERO,
            b"",
            fallback,
            ADDRESS_ZERO,
            0,
            ADDRESS_ZERO,
        ),
    )
    initializer = HexBytes(HexBytes(SAFE_SETUP_FUNC_SELECTOR) + initializer_args)
    if chain_id is None:
        # bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        salt_preimage = encode_packed(
            (
                "bytes32",
                "uint256",
            ),
            (
                keccak(initializer),
                salt_nonce,
            ),
        )
    else:
        # bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce, getChainId()));
        salt_preimage = encode_packed(
            (
                "bytes32",
                "uint256",
                "uint256",
            ),
            (
                keccak(initializer),
                salt_nonce,
                chain_id,
            ),
        )
    salt = keccak(salt_preimage)
    from safe_eth.eth.contracts import load_contract_interface

    bytecode = HexBytes(load_contract_interface("Proxy_V1_4_1.json")["bytecode"])
    deployment_data = encode_packed(
        ["bytes", "uint256"], [bytecode, int(singleton, 16)]
    )
    address = get_create2_address(
        proxy_factory,
        cast(HexStr, salt.hex()),
        cast(HexStr, deployment_data.hex()),
    )
    return (initializer, address)


def format_native_value(value: Wei, chaindata: Optional[ChainData] = None) -> str:
    symbol = chaindata.symbol if chaindata else "ETH"
    if chaindata:
        symbol, decimals = chaindata.symbol, chaindata.decimals
    else:
        symbol, decimals = "ETH", 18
    with localcontext() as ctx:
        ctx.prec = 78
        converted = Decimal(value).scaleb(-decimals).normalize()
    return f"{converted:,f} {symbol}"


def format_wei_value(value: Wei, chaindata: Optional[ChainData] = None) -> str:
    return f"{value} Wei ({format_native_value(value, chaindata)})"


def format_gwei_value(value: Wei, units: tuple[str, str] = ("Wei", "Gwei")) -> str:
    with localcontext() as ctx:
        ctx.prec = 78
        converted = (Decimal(value) / denoms.gwei).normalize()
    wei, gwei = units
    return f"{value} {wei} ({converted:f} {gwei})"


def hexbytes_json_encoder(obj: Any):
    if isinstance(obj, HexBytes):
        return obj.to_0x_hex()
    raise TypeError(f"Cannot serialize object of {type(obj)}")


def hash_eip712_data(data: Any) -> HexBytes:  # using eth_account
    """Compute EIP-712 typed data hash.

    This replicates `eth_account.account.sign_typed_data()` except it
    doesn't require a private key.
    """
    encoded = encode_typed_data(full_message=data)
    return HexBytes(_hash_eip191_message(encoded))


def eip712_data_to_safetx(
    client: "EthereumClient", message: Any, version: str | None = None
) -> "SafeTx":
    from safe_eth.safe import SafeTx

    return SafeTx(
        ethereum_client=client,
        safe_address=message["domain"]["verifyingContract"],
        to=message["message"]["to"],
        value=message["message"]["value"],
        data=HexBytes(message["message"]["data"]),
        operation=message["message"]["operation"],
        safe_tx_gas=message["message"]["safeTxGas"],
        base_gas=message["message"]["dataGas"],  # supports version < 1
        gas_price=message["message"]["gasPrice"],
        gas_token=message["message"]["gasToken"],
        refund_receiver=message["message"]["refundReceiver"],
        signatures=None,
        safe_nonce=message["message"]["nonce"],
        safe_version=version if version else None,
        chain_id=message["domain"].get("chainId"),
    )


def reconstruct_safetx(
    client: "EthereumClient", txfile: TextIO, version: Optional[str]
) -> SafeTxData:
    safetx_json = json.loads(txfile.read())
    safetx = eip712_data_to_safetx(client, safetx_json, version)
    return SafeTxData(
        safetx=safetx,
        data=safetx_json,
        preimage=safetx.safe_tx_hash_preimage,
        hash=safetx.safe_tx_hash,
    )


def parse_signatures(
    owners: list[str], safetxdata: SafeTxData, sigfiles: list[str]
) -> list[SignatureData]:
    sigdata: list[SignatureData] = []
    from safe_eth.safe.safe_signature import SafeSignature

    for sigfile in sigfiles:
        with open(sigfile, "r") as sf:
            sigtext = sf.read().rstrip()
            sigbytes = HexBytes(sigtext)
        siglist = SafeSignature.parse_signature(
            sigbytes, safetxdata.hash, safetxdata.preimage
        )
        if len(siglist) != 1:
            address = None
            sigtype = None
            valid = False
            sig = None
            is_owner = False
        else:
            sig = siglist[0]
            sigtype = sig.__class__.__name__
            owner = sig.owner  # pyright: ignore
            is_owner = owner in owners
            if owner == ADDRESS_ZERO:
                valid = False
                address = None
            else:
                valid = sig.is_valid(
                    safetxdata.safetx.ethereum_client, safetxdata.safetx.safe_address
                )
                address = to_checksum_address(owner)  # pyright: ignore
        sigdata.append(
            SignatureData(
                sig=sig,
                path=sigfile,
                sigbytes=sigbytes,
                address=address,
                sigtype=sigtype,
                is_owner=is_owner,
                valid=valid,
            )
        )
    #     sigobjs.append(siglist[0])
    # safetxdata.safetx.signatures = SafeSignature.export_signatures(sigobjs)
    return sigdata


@contextmanager
def silence_logging():
    log_level = logging.root.manager.disable
    logging.disable(level=100)
    try:
        yield
    finally:
        logging.disable(log_level)
