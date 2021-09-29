{ pkgs ? import <nixpkgs> {}
, libsodium-musig2 ? import ./libsodium.nix { inherit pkgs; }
}:

pkgs.mkShell {
  buildInputs = [pkgs.clang libsodium-musig2];
}
