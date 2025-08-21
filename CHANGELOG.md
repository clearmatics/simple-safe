# Changelog

<!--
----------------------------
      Common Changelog
----------------------------
https://common-changelog.org
----------------------------

Template:

## [vX.Y.Z] - YYYY-MM-DD

### Changed

### Added

### Removed

### Fixed
-->

## [v0.3.0] - 2025-08-20

### Changed

- Rename `build abi-call` to `build call` ([`2f21855`](https://github.com/clearmatics/simple-safe/commit/2f21855))
- Print JSON without additional indentation by default ([`c8ab382`](https://github.com/clearmatics/simple-safe/commit/c8ab382))
- Rename command options in `deploy` and `precompute` ([`50f3957`](https://github.com/clearmatics/simple-safe/commit/50f3957))
- Group `build` Safe transaction options consistently ([`28a3741`](https://github.com/clearmatics/simple-safe/commit/28a3741))
- Reduce default data truncation limit to 500 bytes ([`3aef2b1`](https://github.com/clearmatics/simple-safe/commit/3aef2b1))

### Added

- Support building `--batch` Safe transactions ([#7](https://github.com/clearmatics/simple-safe/issues/7))
- Add `build deploy` command to deploy smart contracts ([`2656b7a`](https://github.com/clearmatics/simple-safe/commit/2656b7a))
- Allow sending value in a Web3 `execTransaction` ([`217e1ad`](https://github.com/clearmatics/simple-safe/commit/217e1ad))
- Add a `--quiet` option to skip information panels ([`71e9c86`](https://github.com/clearmatics/simple-safe/commit/71e9c86))
- Add a `--pretty` option to print JSON with indentation ([`c8ab382`](https://github.com/clearmatics/simple-safe/commit/c8ab382))
- Add an `--expand` option to control data ellipsing ([`a1f127f`](https://github.com/clearmatics/simple-safe/commit/a1f127f))
- Show Call Data Encoder for contract call SafeTxs ([`3867f6e`](https://github.com/clearmatics/simple-safe/commit/3867f6e))

### Removed

- Drop the `--value` option from `build erc20-call` ([`823b6ad`](https://github.com/clearmatics/simple-safe/commit/823b6ad))

### Fixed

- Fix a UI issue where prompt was cleared on backspace ([`0855916`](https://github.com/clearmatics/simple-safe/commit/0855916))
- Fix an error when parsing ABI call string arguments ([`0683f70`](https://github.com/clearmatics/simple-safe/commit/0683f70))

## [v0.2.7] - 2025-08-12

### Fixed

- Restore compatibility with Python 3.11 & 3.12 ([`240ebf3`](https://github.com/clearmatics/simple-safe/commit/240ebf3))

## [v0.2.6] - 2025-08-12

### Changed

- Reword warning when previewing or executing offline ([`bc55c73`](https://github.com/clearmatics/simple-safe/commit/bc55c73))

## [v0.2.5] - 2025-08-10

### Fixed

- Add missing operation validation in `build abi-call` ([`863c7cf`](https://github.com/clearmatics/simple-safe/commit/863c7cf))

## [v0.2.4] - 2025-08-10

### Changed

- Ellipsize printed call data above 1 kilobyte ([`555de3e`](https://github.com/clearmatics/simple-safe/commit/555de3e))

### Added

- Support `DELEGATECALL` Safe transactions ([`34c0666`](https://github.com/clearmatics/simple-safe/commit/34c0666))
- Perform additional validation on TX `--value` ([`77499af`](https://github.com/clearmatics/simple-safe/commit/77499af))

### Fixed

- Restore more helpful Click error messages ([`6e697ed`](https://github.com/clearmatics/simple-safe/commit/6e697ed))

## [v0.2.3] - 2025-08-06

### Fixed

- Prevent potential crash due to RPC node sync issues ([#5](https://github.com/clearmatics/simple-safe/issues/5))

## [v0.2.2] - 2025-08-05

### Fixed

- Fix a regression when signing with a Trezor ([`a422e49`](https://github.com/clearmatics/simple-safe/commit/a422e49))

## [v0.2.1] - 2025-08-05

### Fixed

- Fix wording of warning when gas limit is too low ([`f9f6236`](https://github.com/clearmatics/simple-safe/commit/f9f6236))

## [v0.2.0] - 2025-08-05

### Added

- Support signing a Web3 TX offline without broadcasting ([#3](https://github.com/clearmatics/simple-safe/issues/3))
- Support passing custom Web3 transaction parameters ([#2](https://github.com/clearmatics/simple-safe/issues/2))
- Perform more extensive validation for TXFILEs ([`b3a35dc`](https://github.com/clearmatics/simple-safe/commit/b3a35dc))
- Add an integrated help documentation facility ([#4](https://github.com/clearmatics/simple-safe/issues/4))
- Show recent Safe versions in `--safe-version` help ([`5ada7f8`](https://github.com/clearmatics/simple-safe/commit/5ada7f8))

### Fixed

- Rename Click FUNCTION argument name to match metavar ([`f9e395b`](https://github.com/clearmatics/simple-safe/commit/f9e395b))
- Fix incorrect derivation path in README example ([#1](https://github.com/clearmatics/simple-safe/pull/1))

## [v0.1.6] - 2025-07-22

_First internal release._

[v0.3.0]: https://github.com/clearmatics/simple-safe/releases/tag/v0.3.0
[v0.2.7]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.7
[v0.2.6]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.6
[v0.2.5]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.5
[v0.2.4]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.4
[v0.2.3]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.3
[v0.2.2]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.2
[v0.2.1]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.1
[v0.2.0]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.0
[v0.1.6]: https://github.com/clearmatics/simple-safe/releases/tag/v0.1.6
