import json
import logging
import secrets
from decimal import Decimal
from typing import (
    TYPE_CHECKING,
    NamedTuple,
    Optional,
    Sequence,
    TextIO,
    cast,
)

import click
from hexbytes import (
    HexBytes,
)
from rich.prompt import Confirm

from .abi import Function, find_function, parse_args
from .auth import Authenticator
from .chain import FALLBACK_DECIMALS, fetch_chaindata
from .console import (
    WARNING,
    console,
    get_json_data_renderable,
    get_output_console,
    make_status_logger,
    print_function_matches,
    print_web3_call_data,
    print_web3_tx_fees,
    print_web3_tx_params,
    print_web3_tx_receipt,
)
from .constants import (
    DEFAULT_FALLBACK_ADDRESS,
    DEFAULT_PROXYFACTORY_ADDRESS,
    DEFAULT_SAFE_SINGLETON_ADDRESS,
    DEFAULT_SAFEL2_SINGLETON_ADDRESS,
    SALT_NONCE_SENTINEL,
)
from .util import (
    DeployParams,
    Safe,
    SafeTx,
    SafeVariant,
    to_checksum_address,
)

if TYPE_CHECKING:
    from eth_typing import URI, ChecksumAddress, HexStr
    from web3 import Web3
    from web3.contract import Contract
    from web3.contract.contract import ContractFunction
    from web3.types import Nonce, TxParams, Wei

SAFE_CONTRACT_VERSIONS = (
    "0.0.1",
    "1.0.0",
    "1.1.1",
    "1.2.0",
    "1.3.0",
    "1.4.1",
)

logger = logging.getLogger(__name__)
status = make_status_logger(logger)


class Web3TxOptions(NamedTuple):
    chain_id: int
    gas_limit: Optional[int] = None
    nonce: Optional[int] = None
    max_fee: Optional[int] = None
    max_pri_fee: Optional[int] = None


def get_safe_owners(safe_contract: "Contract") -> list[str]:
    return safe_contract.functions.getOwners().call(block_identifier="latest")


def get_safe_threshold(safe_contract: "Contract") -> int:
    return safe_contract.functions.getThreshold().call(block_identifier="latest")


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
    logging.debug(f"Created Web3Tx: {tx}")
    return tx


def process_call_safetx(
    *,
    w3: "Web3",
    contract: "Contract",
    fn_identifier: str,
    str_args: list[str],
    safe: Safe,
    value: str,
    output: Optional[TextIO],
):
    """Print a SafeTx that represents a contract call."""
    from safe_eth.safe import SafeOperationEnum
    from web3.constants import CHECKSUM_ADDRESSS_ZERO

    match, partials = find_function(contract.abi, fn_identifier)
    if match is None:
        handle_function_match_failure(fn_identifier, partials)
    assert match is not None

    fn_obj = contract.get_function_by_selector(match.selector)
    args = parse_args(fn_obj.abi, str_args)
    calldata = HexBytes(contract.encode_abi(match.sig, args))
    chaindata = fetch_chaindata(safe.chain_id)
    decimals = chaindata.decimals if chaindata else FALLBACK_DECIMALS

    safetx = SafeTx(
        to=contract.address,
        value=int(Decimal(value).scaleb(decimals)),
        data=calldata,
        operation=SafeOperationEnum.CALL.value,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=CHECKSUM_ADDRESSS_ZERO,
        refund_receiver=CHECKSUM_ADDRESSS_ZERO,
    )
    output_console = get_output_console(output)
    output_console.print(
        get_json_data_renderable(safetx.to_eip712_message(safe)),
    )


def process_call_web3tx(
    w3: "Web3",
    *,
    contractfn: "ContractFunction",
    auth: Authenticator,
    force: bool,
    sign_only: bool,
    output: Optional[TextIO],
    txopts: "Web3TxOptions",
    offline: bool,
):
    with status("Building Web3 transaction..."):
        from eth_utils.abi import abi_to_signature
        from web3._utils.contracts import prepare_transaction

        tx_value: Wei = cast("Wei", 0)  # be explicit about zero value
        abi_element_identifier = abi_to_signature(contractfn.abi)
        tx_data = prepare_transaction(
            contractfn.address,
            w3,
            abi_element_identifier=abi_element_identifier,
            contract_abi=contractfn.contract_abi,
            abi_callable=contractfn.abi,
            transaction=cast("TxParams", {"value": tx_value}),
            fn_args=contractfn.args,
            fn_kwargs=contractfn.kwargs,
        ).get("data")
        assert tx_data is not None
        tx = make_web3tx(
            w3,
            from_=auth.address,
            to=contractfn.address,
            txopts=txopts,
            data=tx_data,
            value=tx_value,
        )

    assert "data" in tx
    console.line()
    print_web3_call_data(contractfn, HexBytes(tx["data"]).to_0x_hex())

    assert "chainId" in tx
    with status("Getting chain data..."):
        chaindata = fetch_chaindata(tx["chainId"])
        gasprice = None if offline else w3.eth.gas_price

    console.line()
    print_web3_tx_params(tx, auth, chaindata)
    console.line()
    print_web3_tx_fees(tx, offline, gasprice, chaindata)

    console.line()
    prompt = ("Sign" if sign_only else "Execute") + " Web3 transaction?"
    if not force and not Confirm.ask(prompt, default=False):
        raise click.Abort()

    signed_tx = auth.sign_transaction(tx)
    output_console = get_output_console(output)

    if sign_only:
        console.line()
        output_console.print(get_json_data_renderable(signed_tx._asdict()))
    else:
        with status("Executing Web3 transaction..."):
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        with status("Waiting for Web3 transaction receipt..."):
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        timestamp = w3.eth.get_block(
            tx_receipt["blockNumber"], full_transactions=False
        ).get("timestamp")

        console.line()
        print_web3_tx_receipt(timestamp, tx_receipt, chaindata)

        console.line()
        output_console.print(tx_hash.to_0x_hex())


def handle_function_match_failure(
    identifier: str, partial_matches: Sequence[Function]
) -> None:
    if len(partial_matches) == 0:
        raise click.ClickException(f"No matches for function '{identifier}'.")
    console.line()
    print_function_matches(partial_matches)
    console.line()
    if len(partial_matches) == 1:
        raise click.ClickException(
            f"No match for function '{identifier}'. Did you mean '{partial_matches[0].name}'?"
        )
    else:
        raise click.ClickException(
            "Matched multiple functions. Please specify unique identifier."
        )


def validate_deploy_options(
    *,
    chain_id: Optional[int],
    chain_specific: bool,
    custom_proxy_factory: Optional[str],
    custom_singleton: Optional[str],
    fallback: Optional[str],
    owners: list[str],
    salt_nonce: str,
    threshold: int,
    without_events: bool,
) -> DeployParams:
    if custom_singleton is not None:
        if without_events:
            raise click.ClickException(
                "Option --without-events incompatible with --custom-singleton. "
            )
        singleton_address = custom_singleton
        variant = SafeVariant.UNKNOWN
    elif without_events:
        singleton_address = DEFAULT_SAFE_SINGLETON_ADDRESS
        variant = SafeVariant.SAFE
    else:
        singleton_address = DEFAULT_SAFEL2_SINGLETON_ADDRESS
        variant = SafeVariant.SAFE_L2
    if salt_nonce == SALT_NONCE_SENTINEL:
        salt_nonce_int = secrets.randbits(256)  # uint256
    else:
        salt_nonce_int = int.from_bytes(HexBytes(salt_nonce))
    if chain_specific and chain_id is None:
        raise click.ClickException(
            "Requested chain-specific address but no Chain ID provided."
        )
    elif not chain_specific and chain_id is not None:
        logger.warning(
            f"{WARNING} Ignoring --chain-id {chain_id} because chain-specific address not requested"
        )
        chain_id = None
    return DeployParams(
        proxy_factory=to_checksum_address(
            DEFAULT_PROXYFACTORY_ADDRESS
            if custom_proxy_factory is None
            else custom_proxy_factory
        ),
        singleton=to_checksum_address(singleton_address),
        chain_id=chain_id,
        salt_nonce=salt_nonce_int,
        variant=variant,
        owners=[to_checksum_address(owner) for owner in owners],
        threshold=threshold,
        fallback=to_checksum_address(
            DEFAULT_FALLBACK_ADDRESS if not fallback else fallback
        ),
    )


def validate_safe(
    *,
    safe_address: "ChecksumAddress",
    offline: bool,
    chain_id: Optional[int],
    safe_nonce: Optional[int],
    safe_version: Optional[str],
    w3: "Web3",
) -> tuple[Safe, "Contract"]:
    from safe_eth.eth.contracts import get_safe_contract

    for optname, optval in [
        ("--chain-id", chain_id),
        ("--safe-nonce", safe_nonce),
        ("--safe-version", safe_version),
    ]:
        if offline and optval is None:
            raise click.ClickException(f"Missing {optname} for offline SafeTx")
        elif (not offline) and (optval is not None):
            raise click.ClickException(f"Invalid option {optname} in online mode.")

    if safe_version is not None and safe_version not in SAFE_CONTRACT_VERSIONS:
        raise click.ClickException(
            f"Invalid or unsupported Safe version {safe_version}."
        )

    contract = get_safe_contract(w3, address=safe_address)

    safe = Safe(
        safe_address=safe_address,
        safe_version=safe_version or contract.functions.VERSION().call(),
        safe_nonce=safe_nonce
        if safe_nonce is not None
        else contract.functions.nonce().call(),
        chain_id=chain_id if chain_id is not None else w3.eth.chain_id,
    )
    return (safe, contract)


def validate_rpc_option(rpc: str) -> "Web3":
    from web3 import Web3
    from web3.providers.auto import load_provider_from_uri

    return Web3(load_provider_from_uri(cast("URI", rpc)))


def validate_safetxfile(
    *,
    w3: "Web3",
    txfile: TextIO,
    offline: bool,
    w3_chain_id: Optional[int] = None,
    safe_version: Optional[str] = None,
) -> tuple[Safe, SafeTx, "Contract"]:
    from safe_eth.eth.contracts import get_safe_contract

    message = json.loads(txfile.read())
    safe_address = message["domain"]["verifyingContract"]
    if (
        not offline
        and (tx_chain_id := message["domain"].get("chainId"))
        and w3_chain_id != tx_chain_id
    ):
        raise click.ClickException(
            f"Inconsistent chain IDs. Web3 chain ID is {w3_chain_id} "
            f"but Safe TX chain ID is {tx_chain_id}."
        )
    contract = get_safe_contract(w3, address=safe_address)

    if offline:
        if safe_version is None:
            raise click.ClickException(
                "Missing Safe version, needed when no RPC provided."
            )
        elif safe_version not in SAFE_CONTRACT_VERSIONS:
            raise click.ClickException(
                f"Invalid or unsupported Safe version {safe_version}."
            )
    else:
        actual_version = contract.functions.VERSION().call(block_identifier="latest")
        if (safe_version is not None) and (safe_version != actual_version):
            raise click.ClickException(
                f"Inconsistent Safe versions. Got --safe-version {safe_version} "
                f"but Safe at {safe_address} has version {actual_version}."
            )
        safe_version = actual_version

    assert safe_version is not None

    safe = Safe(
        safe_address=message["domain"]["verifyingContract"],
        safe_version=safe_version,
        safe_nonce=message["message"]["nonce"],
        chain_id=message["domain"].get("chainId"),
    )
    safetx = SafeTx(
        to=message["message"]["to"],
        value=message["message"]["value"],
        data=HexBytes(message["message"]["data"]),
        operation=message["message"]["operation"],
        safe_tx_gas=message["message"]["safeTxGas"],
        base_gas=message["message"]["dataGas"],  # supports version < 1
        gas_price=message["message"]["gasPrice"],
        gas_token=message["message"]["gasToken"],
        refund_receiver=message["message"]["refundReceiver"],
    )
    return (safe, safetx, contract)


def validate_web3tx_options(
    w3: "Web3",
    *,
    chain_id: Optional[int],
    gas_limit: Optional[int],
    nonce: Optional[int],
    max_fee: Optional[str],
    max_pri_fee: Optional[str],
    sign_only: bool,
    offline: bool,
) -> Web3TxOptions:
    from eth_utils.currency import denoms

    if offline and not sign_only:
        raise click.ClickException(
            "Missing RPC node needed to execute Web3 transaction. "
            "To sign offline without executing, pass --sign-only."
        )

    if not offline:
        rpc_chain_id = w3.eth.chain_id
        if chain_id is None:
            chain_id = rpc_chain_id
        elif chain_id != rpc_chain_id:
            raise click.ClickException(
                f"Inconsistent chain IDs. Received --chain-id {chain_id} but RPC chain ID is {rpc_chain_id}."
            )

    txopts = {}
    for optname, optval, w3key in [
        ("--chain-id", chain_id, "chain_id"),
        ("--gas-limit", gas_limit, "gas_limit"),
        ("--nonce", nonce, "nonce"),
        ("--max-fee", max_fee, "max_fee"),
        ("--max-pri-fee", max_pri_fee, "max_pri_fee"),
    ]:
        if optval is not None:
            if w3key in ("max_fee", "max_pri_fee"):
                try:
                    txopts[w3key] = int(Decimal(optval) * denoms.gwei)
                except Exception as exc:
                    raise click.ClickException(
                        f"Could not parse {optname} value '{optval}' or convert it to Wei."
                    ) from exc
                if txopts[w3key] < 0:
                    raise ValueError(
                        f"{optname} must be a positive integer (not '{optval}')."
                    )
            else:
                txopts[w3key] = optval
        elif offline:
            raise click.ClickException(
                f"Missing Web3 parameter {optname} needed to sign offline."
            )

    if (
        "max_fee" in txopts
        and "max_pri_fee" in txopts
        and (max_fee_wei := cast(Optional[int], txopts["max_fee"])) is not None
        and (max_pri_fee_wei := cast(Optional[int], txopts["max_pri_fee"])) is not None
        and (max_pri_fee_wei > max_fee_wei)
    ):
        raise ValueError(
            f"Require max priority fee ({max_pri_fee} Gwei) must be <= max total fee ({max_fee} Gwei)."
        )

    return Web3TxOptions(**txopts)
