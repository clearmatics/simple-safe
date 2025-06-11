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
    version = "3.12";
    uv.enable = true;
    uv.sync.enable = true;
  };

  scripts.safe.exec = ''
    uv run safe "$*";
  '';

  scripts.run-tests.exec = "uv run pytest -s -v --no-header --disable-warnings ./test";

  # See full reference at https://devenv.sh/reference/options/
}
