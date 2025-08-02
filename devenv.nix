{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  packages = [
    pkgs.git
    pkgs.libusb1
    pkgs.taplo
  ];

  env.UV_PYTHON = "${config.env.DEVENV_PROFILE}/bin/python";

  env.LD_LIBRARY_PATH = lib.makeLibraryPath [
    pkgs.libusb1
  ];

  languages.python = {
    enable = true;
    version = "3.13";
    uv.enable = true;
    uv.sync.enable = true;
  };

  env.SOURCE_DIRS = "src/simple_safe test";

  scripts.autofix.exec = ''
    set -ux
    uv sync -q --dev
    uv run ruff check --fix
    uv run ruff check --fix --select I $SOURCE_DIRS
  '';

  scripts.check.exec = ''
    set -ux
    uv sync -q --dev
    uv run ruff check $SOURCE_DIRS
    uv run pyright $SOURCE_DIRS
  '';

  scripts.format.exec = ''
    set -ux
    uv sync -q --dev
    uv run ruff check --fix --select I $SOURCE_DIRS
    uv run ruff format $SOURCE_DIRS
    RUST_LOG=warn taplo fmt pyproject.toml
  '';

  scripts.lint.exec = ''
    set -ux
    uv run ruff check --diff --select I $SOURCE_DIRS
    uv run ruff format --check --diff $SOURCE_DIRS
    RUST_LOG=warn taplo fmt --check --diff pyproject.toml
  '';

  scripts.profile.exec = ''
    set -ux
    IMPORT_LOG=$(mktemp)
    uv run python -X importtime -m simple_safe.safe 2>$IMPORT_LOG
    uv run tuna $IMPORT_LOG
  '';

  env.PYTHON_VERSIONS = "3.11 3.12 3.13";
  env.PYTEST_COMMAND = "pytest -l -s -v --no-header --disable-warnings ./test";
  scripts.runtests.exec = "uv run $PYTEST_COMMAND";
  scripts.runtests-multi.exec = ''
    UV_PYTHON_DOWNLOADS=automatic  # disabled by devenv/Nix
    for PYTHON_VERSION in $PYTHON_VERSIONS; do
      uv run --python $PYTHON_VERSION $PYTEST_COMMAND
    done
  '';

  scripts.pyinstall.exec = ''
    set -ux
    uv python install $PYTHON_VERSIONS
  '';

  # See full reference at https://devenv.sh/reference/options/
}
