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

  languages.python = {
    enable = true;
    version = "3.12";
    uv.enable = true;
    uv.sync.enable = true;
  };

  scripts.safe.exec = ''
    ./safe "$@"
  '';


  # See full reference at https://devenv.sh/reference/options/
}
