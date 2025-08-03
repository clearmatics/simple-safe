import logging
from contextlib import contextmanager
from decimal import Decimal, localcontext
from typing import (
    TYPE_CHECKING,
    Any,
    NamedTuple,
    Optional,
    cast,
)

from hexbytes import (
    HexBytes,
)

from .chaindata import ChainData
from .constants import SAFE_SETUP_FUNC_SELECTOR, SAFE_SETUP_FUNC_TYPES
from .models import (
    SafeInfo,
    Web3TxOptions,
)

if TYPE_CHECKING:
    from eth_account.datastructures import SignedTransaction
    from eth_typing import ChecksumAddress, HexStr
    from safe_eth.safe.safe_signature import SafeSignature
    from web3 import Web3
    from web3.contract import Contract
    from web3.types import Nonce, TxParams, Wei

logger = logging.getLogger(__name__)


class SignatureData(NamedTuple):
    sigbytes: HexBytes
    path: str
    valid: bool
    is_owner: Optional[bool]
    # Invalid signature may not have these fields.
    sig: Optional["SafeSignature"]
    sigtype: Optional[str]
    address: Optional["ChecksumAddress"]


def as_checksum(checksum_str: str) -> "ChecksumAddress":
    """Cast to satisfy type checker."""
    return cast("ChecksumAddress", checksum_str)


def compute_safe_address(
    *,
    chain_id: Optional[int],
    fallback: "ChecksumAddress",
    owners: list["ChecksumAddress"],
    proxy_factory: "ChecksumAddress",
    salt_nonce: int,
    singleton: "ChecksumAddress",
    threshold: int,
) -> tuple[HexBytes, "ChecksumAddress"]:
    """Compute Safe address via SafeProxyFactory v1.4.1."""
    from eth_abi.abi import encode as abi_encode
    from eth_abi.packed import encode_packed
    from eth_utils.crypto import keccak
    from safe_eth.eth.contracts import load_contract_interface
    from web3.constants import ADDRESS_ZERO
    from web3.utils.address import get_create2_address

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

    bytecode = HexBytes(load_contract_interface("Proxy_V1_4_1.json")["bytecode"])
    deployment_data = encode_packed(
        ["bytes", "uint256"], [bytecode, int(singleton, 16)]
    )
    address = get_create2_address(
        proxy_factory,
        cast("HexStr", salt.hex()),
        cast("HexStr", deployment_data.hex()),
    )
    return (initializer, address)


def format_native_value(value: "Wei", chaindata: Optional[ChainData] = None) -> str:
    symbol = chaindata.symbol if chaindata else "ETH"
    if chaindata:
        symbol, decimals = chaindata.symbol, chaindata.decimals
    else:
        symbol, decimals = "ETH", 18
    with localcontext() as ctx:
        ctx.prec = 78
        converted = Decimal(value).scaleb(-decimals).normalize()
    return f"{converted:,f} {symbol}"


def format_wei_value(value: "Wei", chaindata: Optional[ChainData] = None) -> str:
    return f"{value} Wei ({format_native_value(value, chaindata)})"


def format_gwei_value(value: "Wei", units: tuple[str, str] = ("Wei", "Gwei")) -> str:
    from eth_utils.currency import denoms

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
    from eth_account.messages import (
        _hash_eip191_message,  # pyright: ignore[reportPrivateUsage]
        encode_typed_data,
    )

    encoded = encode_typed_data(full_message=data)
    return HexBytes(_hash_eip191_message(encoded))


def make_offline_web3() -> "Web3":
    from web3 import Web3
    from web3.providers.base import BaseProvider

    return Web3(provider=BaseProvider())


def make_web3tx(
    w3: "Web3",
    *,
    from_: "ChecksumAddress",
    to: "ChecksumAddress",
    txopts: "Web3TxOptions",
    data: "bytes | HexStr",
    value: "Wei",
) -> "TxParams":
    from web3.types import TxParams

    assert txopts.chain_id is not None
    if (gas_limit := txopts.gas_limit) is None:
        gas_limit = w3.eth.estimate_gas({"to": to, "data": data})
    if (nonce := txopts.nonce) is None:
        nonce = w3.eth.get_transaction_count(from_, block_identifier="pending")
    if (max_pri_fee := txopts.max_pri_fee) is None:
        max_pri_fee = w3.eth.max_priority_fee
    if (max_fee := txopts.max_fee) is None:
        block = w3.eth.get_block("latest")
        assert "baseFeePerGas" in block
        max_fee = (2 * block["baseFeePerGas"]) + max_pri_fee
    tx = TxParams(
        type=2,
        to=to,
        chainId=txopts.chain_id,
        gas=gas_limit,
        nonce=cast("Nonce", nonce),
        maxFeePerGas=cast("Wei", max_fee),
        maxPriorityFeePerGas=cast("Wei", max_pri_fee),
        data=data,
        value=value,
    )
    logger.info(f"Created Web3Tx: {tx}")
    return tx


def parse_signatures(
    safetx_hash: HexBytes,
    safetx_preimage: HexBytes,
    sigfiles: list[str],
    owners: Optional[list["ChecksumAddress"]],
) -> list[SignatureData]:
    sigdata: list[SignatureData] = []
    from eth_utils.address import to_checksum_address
    from safe_eth.safe.safe_signature import SafeSignature
    from web3.constants import ADDRESS_ZERO

    for sigfile in sigfiles:
        with open(sigfile, "r") as sf:
            sigtext = sf.read().rstrip()
            sigbytes = HexBytes(sigtext)
        siglist = SafeSignature.parse_signature(sigbytes, safetx_hash, safetx_preimage)
        if len(siglist) != 1:
            address = None
            sigtype = None
            valid = False
            sig = None
            is_owner = False
        else:
            sig = siglist[0]
            sigtype = sig.__class__.__name__
            sig_owner = sig.owner  # pyright: ignore
            if owners is not None:
                is_owner = sig_owner in owners
            else:
                is_owner = None
            if sig_owner == ADDRESS_ZERO:
                valid = False
                address = None
            else:
                # At this point, because len(siglist)==1, it's a valid ECDSA
                # signature. It's just the address might not correspond to an
                # actual owner.
                valid = True
                address = to_checksum_address(sig_owner)  # pyright: ignore
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
    return sigdata


def query_safe_info(safe_contract: "Contract"):
    return SafeInfo(
        owners=safe_contract.functions.getOwners().call(block_identifier="latest"),
        threshold=safe_contract.functions.getThreshold().call(
            block_identifier="latest"
        ),
    )


def scale_decimal_value(value: str, decimals: int) -> int:
    scaled_value = int(Decimal(value).scaleb(decimals))
    logger.debug(f"Scaled value '{value}' to '{scaled_value}' ({decimals} decimals)")
    return scaled_value


def signed_tx_to_dict(signed_tx: "SignedTransaction") -> dict[str, str]:
    res: dict[str, str] = {}
    for key, val in signed_tx._asdict().items():
        if isinstance(val, HexBytes):
            res[key] = val.to_0x_hex()
        else:
            res[key] = val
    return res


@contextmanager
def silence_logging():
    log_level = logging.root.manager.disable
    logging.disable(level=100)
    try:
        yield
    finally:
        logging.disable(log_level)


def to_checksum_address(address: str) -> "ChecksumAddress":
    from eth_utils.address import to_checksum_address

    return to_checksum_address(address)
