import json
from decimal import Decimal, localcontext
from typing import (
    Any,
    NamedTuple,
    Optional,
    TextIO,
    cast,
)

from eth_account.messages import (
    _hash_eip191_message,  # pyright: ignore[reportPrivateUsage]
    encode_typed_data,
)
from eth_typing import ChecksumAddress
from eth_utils.address import to_checksum_address
from eth_utils.currency import denoms
from hexbytes import (
    HexBytes,
)
from safe_eth.eth import EthereumClient
from safe_eth.eth.constants import NULL_ADDRESS
from safe_eth.safe import SafeTx
from safe_eth.safe.safe_signature import SafeSignature
from web3.types import Wei

from .chain import ChainData


class SafeTxData(NamedTuple):
    safetx: SafeTx
    payload: dict[str, Any]
    preimage: HexBytes
    hash: HexBytes


class SignatureData(NamedTuple):
    sigbytes: HexBytes
    path: str
    valid: bool
    is_owner: bool
    # Invalid signature may not have these fields.
    sig: Optional[SafeSignature]
    sigtype: Optional[str]
    address: Optional[ChecksumAddress]


def as_checksum(checksum_str: str) -> ChecksumAddress:
    """Cast to satisfy type checker."""
    return cast(ChecksumAddress, checksum_str)


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


def format_gwei_value(value: Wei) -> str:
    with localcontext() as ctx:
        ctx.prec = 78
        converted = (Decimal(value) / denoms.gwei).normalize()
    return f"{value} Wei ({converted:f} Gwei)"


def hexbytes_json_encoder(obj: Any):
    if isinstance(obj, HexBytes):
        return obj.to_0x_hex()
    raise TypeError(f"Cannot serialize object of {type(obj)}")


def hash_eip712_data(data: Any) -> HexBytes:  # using eth_account
    encoded = encode_typed_data(full_message=data)
    return HexBytes(_hash_eip191_message(encoded))


def eip712_data_to_safetx(
    client: EthereumClient, message: Any, version: str | None = None
) -> SafeTx:
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
    client: EthereumClient, txfile: TextIO, version: Optional[str]
) -> SafeTxData:
    safetx_json = json.loads(txfile.read())
    safetx = eip712_data_to_safetx(client, safetx_json, version)
    return SafeTxData(
        safetx=safetx,
        payload=safetx.eip712_structured_data,
        preimage=safetx.safe_tx_hash_preimage,
        hash=safetx.safe_tx_hash,
    )


def parse_signatures(
    owners: list[str], safetxdata: SafeTxData, sigfiles: list[str]
) -> list[SignatureData]:
    sigdata: list[SignatureData] = []
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
            if owner == NULL_ADDRESS:
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
