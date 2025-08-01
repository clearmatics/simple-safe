import dataclasses
import logging
from contextlib import contextmanager
from decimal import Decimal, localcontext
from enum import Enum
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

from .chain import ChainData
from .constants import SAFE_SETUP_FUNC_SELECTOR, SAFE_SETUP_FUNC_TYPES

if TYPE_CHECKING:
    from eth_typing import URI, ChecksumAddress, HexStr
    from safe_eth.safe import SafeTx as SafeLibTx
    from safe_eth.safe.safe_signature import SafeSignature
    from web3 import Web3
    from web3.contract import Contract
    from web3.types import Wei


@dataclasses.dataclass(kw_only=True)
class DeployParams:
    # deployment
    proxy_factory: "ChecksumAddress"
    singleton: "ChecksumAddress"
    chain_id: Optional[int]
    salt_nonce: int
    variant: "SafeVariant"
    # initialization
    owners: list["ChecksumAddress"]
    threshold: int
    fallback: "ChecksumAddress"


class SafeVariant(Enum):
    SAFE = 1
    SAFE_L2 = 2
    UNKNOWN = 3


class Safe(NamedTuple):
    safe_address: "ChecksumAddress"
    safe_version: str
    safe_nonce: int
    chain_id: int


class SafeInfo(NamedTuple):
    owners: Optional[list["ChecksumAddress"]] = None
    threshold: Optional[int] = None


class SafeTx(NamedTuple):
    to: "ChecksumAddress"
    value: int
    data: HexBytes
    operation: int
    safe_tx_gas: int
    base_gas: int
    gas_price: int
    gas_token: "ChecksumAddress"
    refund_receiver: "ChecksumAddress"

    def _to_safelibtx(
        self,
        safe: Safe,
    ) -> "SafeLibTx":
        from safe_eth.eth import EthereumClient
        from safe_eth.safe import SafeTx as SafeLibTx

        return SafeLibTx(
            ethereum_client=EthereumClient(ethereum_node_url=cast("URI", "dummy")),
            safe_address=safe.safe_address,
            to=self.to,
            value=self.value,
            data=self.data,
            operation=self.operation,
            safe_tx_gas=self.safe_tx_gas,
            base_gas=self.base_gas,
            gas_price=self.gas_price,
            gas_token=self.gas_token,
            refund_receiver=self.refund_receiver,
            signatures=None,  # signatures are not part of EIP-712 data
            safe_nonce=safe.safe_nonce,
            safe_version=safe.safe_version,
            chain_id=safe.chain_id,
        )

    def hash(
        self,
        safe: Safe,
    ) -> HexBytes:
        return self._to_safelibtx(safe).safe_tx_hash

    def preimage(
        self,
        safe: Safe,
    ) -> HexBytes:
        return self._to_safelibtx(safe).safe_tx_hash_preimage

    def to_eip712_message(
        self,
        safe: Safe,
    ) -> dict[str, Any]:
        safetx = self._to_safelibtx(safe)
        return safetx.eip712_structured_data


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
    from safe_eth.eth.contracts import load_contract_interface

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
