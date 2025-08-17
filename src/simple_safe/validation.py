import json
import logging
import secrets
from decimal import Decimal, InvalidOperation
from typing import (
    TYPE_CHECKING,
    Any,
    Iterable,
    NamedTuple,
    Optional,
    Sequence,
    TextIO,
    cast,
)

import click
from click.core import ParameterSource
from hexbytes import (
    HexBytes,
)

from .console import (
    SYMBOL_WARNING,
    make_status_logger,
)
from .constants import (
    DEFAULT_FALLBACK_ADDRESS,
    DEFAULT_PROXYFACTORY_ADDRESS,
    DEFAULT_SAFE_SINGLETON_ADDRESS,
    DEFAULT_SAFEL2_SINGLETON_ADDRESS,
    SAFE_CONTRACT_VERSIONS,
    SALT_SENTINEL,
)
from .types import (
    DeployParams,
    Safe,
    SafeTx,
    SafeVariant,
    Web3TxOptions,
)
from .util import hash_eip712_data, to_checksum_address, to_json

if TYPE_CHECKING:
    from eth_typing import URI, ChecksumAddress
    from web3 import Web3
    from web3.contract import Contract


logger = logging.getLogger(__name__)
status = make_status_logger(logger)


# ┌──────────────────────────┐
# │ Option Validator Helpers │
# └──────────────────────────┘


class CLIOption(NamedTuple):
    name: str
    value: Optional[Any]
    source: Optional[ParameterSource]


# ┌───────────────────┐
# │ Option Validators │
# └───────────────────┘


def validate_batch_options(
    options: Iterable[CLIOption],
    colnames: Iterable[str],
):
    """Validate options and CSV columns for batch mode."""
    csv_columns: set[str] = set(colnames)
    cli_options: set[str] = set()
    cli_default: set[str] = set()
    all_options: set[str] = set()
    for option in options:
        all_options.add(option.name)
        if option.source == ParameterSource.COMMANDLINE:
            cli_options.add(option.name)
        elif (option.value is not None) and option.source == ParameterSource.DEFAULT:
            cli_default.add(option.name)

    # CLI options must not overlap with CSV columns
    if overlap := cli_options & csv_columns:
        raise click.ClickException(
            f"Duplicate CLI options and CSV columns: {overlap}. "
            "Either omit the CLI option or drop the CSV column."
        )

    # must have a value for every option
    if not all_options <= (have_value := (cli_options | cli_default | csv_columns)):
        raise click.ClickException(
            f"Missing values for CLI options or CSV columns: {all_options - have_value}."
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
    if salt_nonce == SALT_SENTINEL:
        salt_nonce_int = secrets.randbits(256)  # uint256
    else:
        salt_nonce_int = int.from_bytes(HexBytes(salt_nonce))
    if chain_specific and chain_id is None:
        raise click.ClickException(
            "Requested chain-specific address but no Chain ID provided."
        )
    elif not chain_specific and chain_id is not None:
        logger.warning(
            f"{SYMBOL_WARNING} Ignoring --chain-id {chain_id} because chain-specific address not requested"
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


def validate_funcarg_columns(colnames: Iterable[str], argnames: Sequence[str]):
    """Check every argname (or its variant) appears in `colnames` exactly once."""
    arglen = len(argnames)
    _argnames = ["arg:" + name for name in argnames]
    _altnames = ["arg:" + str(1 + i) for i in range(arglen)]
    matched = [False] * arglen
    done: set[str] = set()
    used: dict[str, str] = {}
    for field in colnames:
        if field in done:
            raise click.ClickException(
                f"Duplicate function argument column '{field}' in CSV file."
            )
        elif (in_arg := (field in _argnames)) or (field in _altnames):
            index = _argnames.index(field) if in_arg else _altnames.index(field)
            matched[index] = True
            done.add(_argnames[index])
            done.add(_altnames[index])
            used[field] = argnames[index]

    if not all(matched):
        missing = set(
            [name for (name, match) in zip(argnames, matched) if match is False]
        )
        raise click.ClickException(
            f"Missing {arglen - sum(matched)} function arguments: {missing}."
        )

    logger.info(
        f"Mapping CSV columns {tuple(used.keys())} "
        f"to function arguments {tuple(used.values())}"
    )


def validate_rpc_option(rpc: str) -> "Web3":
    from web3 import Web3
    from web3.providers.auto import load_provider_from_uri

    return Web3(load_provider_from_uri(cast("URI", rpc)))


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
            raise click.ClickException(f"Missing {optname} for offline SafeTx.")
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


def validate_decimal_value(value: str) -> Decimal:
    try:
        decval = Decimal(value)
    except InvalidOperation as exc:
        raise click.ClickException(f"Cannot parse value '{value}' as Decimal.") from exc
    if decval < 0:
        raise click.ClickException(f"Value '{value}' must be positive.")
    return decval


def validate_safetxfile(
    *,
    w3: "Web3",
    txfile: TextIO,
    offline: bool,
    w3_chain_id: Optional[int] = None,
    safe_version: Optional[str] = None,
) -> tuple[Safe, SafeTx, "Contract"]:
    from safe_eth.eth.contracts import get_safe_contract

    def abort_invalid():
        raise click.ClickException(
            f"TXFILE '{txfile.name}' is not a valid representation of an EIP-712 Safe transaction."
        )

    message = json.loads(txfile.read())
    if ("types" not in message) or ("SafeTx" not in message["types"]):
        abort_invalid()
    safetx_hash = hash_eip712_data(
        message
    )  # Use `eth_account` to validate EIP-712 message
    logger.debug(f"SafeTx Hash: {safetx_hash.to_0x_hex()}")
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
    logger.info(f"Safe: {safe._asdict()}")
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
    logger.info(f"SafeTx: {to_json(safetx._asdict())}")

    if safetx_hash != safetx.hash(safe):
        abort_invalid()

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
