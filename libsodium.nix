{ pkgs ? import <nixpkgs> {} }:

pkgs.libsodium.overrideAttrs (oldAttrs: {
    name = "libsodium-1.0.18-musig2";
    src = pkgs.fetchFromGitHub {
      owner = "input-output-hk";
      repo = "libsodium";
      # branch musig2_compat
      rev = "7f9f211fcc88d8f0d7a821e5b9041268c392300a";
      sha256 = "0527x23z1h4ny492jjmyxpwb48hrlbgibin83w1qm0jqvg441xgp";
    };
    nativeBuildInputs = [ pkgs.autoreconfHook ];
    configureFlags = "--enable-static";
  })
