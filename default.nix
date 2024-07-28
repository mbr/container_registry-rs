# TODO: This file is leftover from rockslide and needs to be updated.
let
  rust-overlay = (import (builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/7c94410d52d4e8bd72803fc1fe6c51fe179edaf5.tar.gz"));
in { pkgs ? (import <nixpkgs>) { overlays = [ rust-overlay ]; } }:
let
  # MacOS X is supported as tier 2, for development purposes.
  isMacOS = pkgs.stdenv.isDarwin;
  # We compile to a static binary on Linux, which is also used to create releases, otherwise use the default.
  # Right now, we hardcode Apple silicon macs.
  target = if isMacOS then "aarch64-apple-darwin" else "x86_64-unknown-linux-musl";
  stable-rust = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "rust-src" ];
    targets = [ target ];
  };
  rustPlatform = pkgs.makeRustPlatform {
    cargo = stable-rust;
    rustc = stable-rust;
  };
  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in rustPlatform.buildRustPackage {
  name = cargoToml.package.name;
  version = cargoToml.package.version;
  src = pkgs.lib.cleanSourceWith {
    filter = name: type: baseNameOf name != "target";
    src = (pkgs.lib.cleanSource ./.);
  };
  cargoLock = { lockFile = ./Cargo.lock; };
  # Note that we don't really need `podman` as a native build input, but it is
  # helpful for running locally in a `nix-shell`.
  nativeBuildInputs = with pkgs; [ podman ]
    ++ (if isMacOS then with darwin.apple_sdk.frameworks; [ SystemConfiguration qemu ] else []);
  buildPhase = ''
    cargo build --release --offline --target=${target} --features bin
  '';
  installPhase = ''
    mkdir -p $out/bin
    cp target/${target}/release/container-registry $out/bin
  '';
}
