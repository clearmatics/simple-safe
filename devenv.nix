{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  packages = [ pkgs.git ];

  languages.python = {
    enable = true;
    version = "3.12";
    uv.enable = true;
    uv.sync.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
