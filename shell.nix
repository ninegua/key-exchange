{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  dfx-env = import (fetchTarball
    "https://github.com/ninegua/ic-nix/releases/latest/download/dfx-env.tar.gz")
    { };
in dfx-env.overrideAttrs (old: {
  # disable icp-cli telemetry
  DO_NOT_TRACK = 1;
  DFX_WARNING = "-mainnet_plaintext_identity";
  buildInputs = old.buildInputs ++ [ nodejs prettier go-grip ];
})
