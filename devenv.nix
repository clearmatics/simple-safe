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
    pkgs.taplo
  ];

  env.UV_PYTHON = "${config.env.DEVENV_PROFILE}/bin/python";

  dotenv.enable = true;

  languages.python = {
    enable = true;
    version = "3.13";
    uv.enable = true;
    uv.sync.enable = true;
  };

  env.SOURCE_DIRS = "src/simple_safe test";

  scripts.check.exec = ''
    set -ux
    uv sync --dev
    uv run ruff check $SOURCE_DIRS
    uv run pyright $SOURCE_DIRS
  '';

  scripts.format.exec = ''
    set -ux
    uv sync --dev
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

  env.PYTHON_VERSIONS = "3.11 3.12 3.13";
  env.PYTEST_COMMAND = "pytest -l -s -v --no-header --disable-warnings ./test";
  scripts.testrun.exec = "uv run $PYTEST_COMMAND";
  scripts.testrun-multi.exec = ''
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
