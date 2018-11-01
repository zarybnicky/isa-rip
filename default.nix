{ pkgs ? import <nixpkgs> {} }:
with pkgs;
stdenv.mkDerivation rec {
  name = "isa-rip";
  src = ./.;
  nativeBuildInputs = [ libpcap pandoc ];
}
