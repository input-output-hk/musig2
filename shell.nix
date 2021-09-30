{ pkgs ? import <nixpkgs> { }
, libsodium-musig2 ? import ./libsodium.nix { inherit pkgs; }
}:

pkgs.mkShell {
  buildInputs = [
    # build musig2test
    pkgs.clang
    libsodium-musig2
    # verify signature haskell script
    pkgs.cabal-install
    pkgs.ghc
  ];
}
