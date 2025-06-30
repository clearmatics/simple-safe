DEPLOY_SAFE_VERSION = "1.4.1"
SALT_NONCE_SENTINEL = "random"

# Safe v1.4.1 canonical addresses
DEFAULT_FALLBACK_ADDRESS = "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"
DEFAULT_PROXYFACTORY_ADDRESS = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"
DEFAULT_SAFEL2_SINGLETON_ADDRESS = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"
DEFAULT_SAFE_SINGLETON_ADDRESS = "0x41675C099F32341bf84BFc5382aF534df5C7461a"

# Safe v1.4.1 setup() function
# setup(address[],uint256,address,bytes,address,address,uint256,address)
SAFE_SETUP_FUNC_SELECTOR = "0xb63e800d"
SAFE_SETUP_FUNC_TYPES = (
    "address[]",
    "uint256",
    "address",
    "bytes",
    "address",
    "address",
    "uint256",
    "address",
)
