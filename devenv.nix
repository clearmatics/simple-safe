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

  scripts.run-tests.exec = "uv run pytest -l -s -v --no-header --disable-warnings ./test";

  # See full reference at https://devenv.sh/reference/options/
}
