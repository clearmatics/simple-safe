import json
import logging
import tomllib
from pathlib import Path
from typing import NamedTuple, Optional

import platformdirs
import tomli_w

APP_NAME = "simple-safe"
APP_AUTHOR = "Clearmatics"
CHAINLIST_URL = "https://chainlist.org/rpcs.json"

FALLBACK_DECIMALS = 18


logger = logging.getLogger(__name__)


class ChainData(NamedTuple):
    chain_id: int
    name: str
    symbol: str
    decimals: int


class ChainDataPaths(NamedTuple):
    cache_dir: Path
    metadata: Path
    chaindata: Path


def get_paths() -> ChainDataPaths:
    cache_dir = platformdirs.user_cache_path(appname=APP_NAME, appauthor=APP_AUTHOR)
    return ChainDataPaths(
        cache_dir=cache_dir,
        metadata=cache_dir / "metadata.toml",
        chaindata=cache_dir / "chaindata.json",
    )


def parse_etag(etag: str) -> str:
    split = etag.split('"')
    if len(split) != 3:
        raise ValueError(f"Invalid ETag: <{etag}>.")
    return split[-2]


def lookup_chaindata(datafile: Path, chain_id: int) -> Optional[ChainData]:
    if not datafile.exists():
        return None
    with datafile.open("rb") as fp:
        chaindata = json.load(fp)
    for chain in chaindata:
        if chain["chainId"] == chain_id and chain["nativeCurrency"]["decimals"] >= 0:
            return ChainData(
                chain_id=chain_id,
                name=chain["nativeCurrency"]["name"],
                symbol=chain["nativeCurrency"]["symbol"],
                decimals=chain["nativeCurrency"]["decimals"],
            )
    return None


def fetch_chaindata(chain_id: int) -> Optional[ChainData]:
    import requests

    paths = get_paths()
    if not paths.cache_dir.exists():
        logger.debug(f"Creating cache dir '{paths.cache_dir}'")
        paths.cache_dir.mkdir(mode=0o700, parents=True)
    elif not paths.cache_dir.is_dir():
        raise NotADirectoryError(
            f"Cache directory '{paths.cache_dir}' must be a directory."
        )

    chaindata = lookup_chaindata(paths.chaindata, chain_id)
    if chaindata:
        logger.debug(f"Cache hit for chain ID {chain_id}")
        return chaindata

    metadata = {}
    old_etag = None
    if paths.chaindata.exists():
        with open(paths.metadata, "rb") as fp:
            metadata = tomllib.load(fp)
        if "chains" in metadata:
            old_etag = metadata["chains"].get("etag")
            res = requests.head(CHAINLIST_URL, headers={"If-None-Match": old_etag})
            new_etag_value = res.headers.get("etag")
            if new_etag_value:
                new_etag = parse_etag(new_etag_value)
                if new_etag == old_etag:
                    logger.debug("ChainList data unchanged")
                    return None

    logger.debug("Requesting ChainList data")
    res = requests.get(CHAINLIST_URL)
    assert len(res.content) > 0, "Bad ChainList data."
    with open(paths.chaindata, "wb") as fp:
        fp.write(res.content)
    metadata["chains"] = {}
    new_etag_value = res.headers.get("etag")
    if new_etag_value:
        metadata["chains"]["etag"] = parse_etag(new_etag_value)
        with open(paths.metadata, "wb") as fp:
            tomli_w.dump(metadata, fp)

    return lookup_chaindata(paths.chaindata, chain_id)
