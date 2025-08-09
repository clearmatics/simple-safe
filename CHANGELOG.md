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

## [v0.2.4] - 2025-08-10

### Changed

- Ellipsize printed call data above 1 kilobyte ([`555de3e`](https://github.com/clearmatics/simple-safe/commit/555de3e))

### Added

- Support `DELEGATECALL` Safe transactions ([`34c0666`](https://github.com/clearmatics/simple-safe/commit/34c0666))
- Perform additional validation on TX `--value` ([`77499af`](https://github.com/clearmatics/simple-safe/commit/77499af))

### Fixed

- Restore more helpful Click error messages ([`cdddc91`](https://github.com/clearmatics/simple-safe/commit/cdddc91))

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
- Show recent Safe versions in --safe-version help ([`5ada7f8`](https://github.com/clearmatics/simple-safe/commit/5ada7f8))

### Fixed

- Rename Click FUNCTION argument name to match metavar ([`f9e395b`](https://github.com/clearmatics/simple-safe/commit/f9e395b))
- Fix incorrect derivation path in README example ([#1](https://github.com/clearmatics/simple-safe/pull/1))

## [v0.1.6] - 2025-07-22

_First internal release._

[v0.2.4]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.4
[v0.2.3]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.3
[v0.2.2]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.2
[v0.2.1]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.1
[v0.2.0]: https://github.com/clearmatics/simple-safe/releases/tag/v0.2.0
[v0.1.6]: https://github.com/clearmatics/simple-safe/releases/tag/v0.1.6
