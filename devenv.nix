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

  env.SOURCE_DIRS = "src/simple_safe tests";

  scripts.autofix.exec = ''
    uv sync -q --dev
    uv run -q ruff check --fix
    uv run -q ruff check --fix --select I $SOURCE_DIRS
  '';

  scripts.check.exec = ''
    uv sync -q --dev
    uv run -q ruff check $SOURCE_DIRS
    uv run -q pyright $SOURCE_DIRS
  '';

  scripts.format.exec = ''
    set -ux
    uv sync -q --dev
    uv run -q ruff check --fix --select I $SOURCE_DIRS
    uv run -q ruff format $SOURCE_DIRS
    RUST_LOG=warn taplo fmt pyproject.toml
  '';

  scripts.lint.exec = ''
    uv run -q ruff check --diff --select I $SOURCE_DIRS
    uv run -q ruff format --check --diff $SOURCE_DIRS
    RUST_LOG=warn taplo fmt --check --diff pyproject.toml
  '';

  scripts.profile.exec = ''
    set -ux
    IMPORT_LOG=$(mktemp)
    uv run -q python -X importtime -m simple_safe.safe 2>$IMPORT_LOG
    uv run -q tuna $IMPORT_LOG
  '';

  env.PYTHON_VERSIONS = "3.11 3.12 3.13";
  env.PYTEST_COMMAND = "pytest -l -s -v --no-header --disable-warnings ./tests";
  scripts.runtests.exec = "uv run -q $PYTEST_COMMAND";
  scripts.runtests-multi.exec = ''
    UV_PYTHON_DOWNLOADS=automatic  # disabled by devenv/Nix
    for PYTHON_VERSION in $PYTHON_VERSIONS; do
      uv run -q --python $PYTHON_VERSION $PYTEST_COMMAND
    done
  '';

  scripts.pyinstall.exec = ''
    uv python install $PYTHON_VERSIONS
  '';

  # See full reference at https://devenv.sh/reference/options/
}
