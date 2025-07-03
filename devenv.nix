{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  packages = [ pkgs.git ];

  env.UV_PYTHON = "${config.env.DEVENV_PROFILE}/bin/python";

  dotenv.enable = true;

  languages.python = {
    enable = true;
    version = "3.13";
    uv.enable = true;
    uv.sync.enable = true;
  };

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
