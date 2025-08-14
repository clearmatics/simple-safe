import dataclasses
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

if TYPE_CHECKING:
    from eth_typing import URI, ABIFunction, ChecksumAddress
    from safe_eth.safe import SafeTx as SafeLibTx
    from safe_eth.safe.safe_signature import SafeSignature


class ContractCall:
    def __init__(self, fn_abi: "ABIFunction", args: tuple[Any, ...]):
        from eth_utils.abi import (
            abi_to_signature,
            function_abi_to_4byte_selector,
            get_abi_input_names,
            get_abi_input_types,
        )

        self.abi = fn_abi
        self.args = args
        self.argtypes = list(map(str, get_abi_input_types(fn_abi)))
        self.argnames = list(map(str, get_abi_input_names(fn_abi)))
        self.signature = abi_to_signature(fn_abi)
        self.selector = HexBytes(function_abi_to_4byte_selector(fn_abi)).to_0x_hex()


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


class SafeOperation(Enum):
    CALL = 0
    DELEGATECALL = 1


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
            signatures=None,  # Signatures are not part of EIP-712 data
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
        typed_data = safetx.eip712_structured_data
        typed_data["message"]["data"] = typed_data["message"]["data"].to_0x_hex()
        return typed_data


class SignatureData(NamedTuple):
    sigbytes: HexBytes
    path: str
    valid: bool
    is_owner: Optional[bool]
    # Invalid signature may not have these fields.
    sig: Optional["SafeSignature"]
    sigtype: Optional[str]
    address: Optional["ChecksumAddress"]


class Web3TxOptions(NamedTuple):
    chain_id: int
    gas_limit: Optional[int] = None
    nonce: Optional[int] = None
    max_fee: Optional[int] = None
    max_pri_fee: Optional[int] = None
