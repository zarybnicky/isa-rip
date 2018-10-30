{ pkgs ? import <nixpkgs> {} }:
pkgs.stdenv.mkDerivation rec {
  name = "isa-rip";
  src = ./.;
  nativeBuildInputs = [ pkgs.libpcap ];
}
