from safe_eth.eth import EthereumClient
from safe_eth.safe import Safe
from safe_eth.safe import SafeTx

ETHEREUM_NODE_URL = "https://sepolia.drpc.org"


def get_safe():
    safe_address = "0xb6e46b8Ad163C68d736Ec4199F43033B43379c70"
    ethereum_client = EthereumClient(ETHEREUM_NODE_URL)  # pyright: ignore[reportArgumentType]
    return Safe(safe_address, ethereum_client)  # pyright: ignore[reportAbstractUsage, reportArgumentType]


def main():
    safe = get_safe()
    safe_info = safe.retrieve_all_info()
    print(safe_info)


if __name__ == "__main__":
    main()
