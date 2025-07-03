from dataclasses import asdict

from eth_utils.address import to_checksum_address

from simple_safe.constants import (
    DEFAULT_FALLBACK_ADDRESS,
    DEFAULT_PROXYFACTORY_ADDRESS,
    DEFAULT_SAFE_SINGLETON_ADDRESS,
    DEFAULT_SAFEL2_SINGLETON_ADDRESS,
)
from simple_safe.util import DeployParams, SafeVariant, compute_safe_address


def test_happy_path():
    owner = to_checksum_address("0xdeadbeef00000000000000000000000000000000")
    params = DeployParams(
        proxy_factory=to_checksum_address(DEFAULT_PROXYFACTORY_ADDRESS),
        singleton=to_checksum_address(DEFAULT_SAFEL2_SINGLETON_ADDRESS),
        salt_nonce=0,
        variant=SafeVariant.SAFE_L2,
        owners=[owner],
        threshold=1,
        fallback=to_checksum_address(DEFAULT_FALLBACK_ADDRESS),
        chain_id=None,
    )
    params = asdict(params)
    params.pop("variant")
    _, address = compute_safe_address(**params)
    assert address == "0x1B751A15d6aEd26aC3e2A5320548F390ccE76ED2"

    params.update(
        singleton=to_checksum_address(DEFAULT_SAFE_SINGLETON_ADDRESS),
    )
    _, address = compute_safe_address(**params)
    assert address == "0x09e5830Fdf94340474B54fCDE0F3A2d408Df56DE"

    params.update(salt_nonce=123)
    _, address = compute_safe_address(**params)
    assert address == "0x06bA263c7Fd42Ac736e7b782540693696Cf7D9Ec"

    params.update(chain_id=1)
    _, address = compute_safe_address(**params)
    assert address == "0x5381010Eb5716fda6f37B56655edebFEe57C5e38"
