{ pkgs ? import <nixpkgs> {} }:
with pkgs;
stdenv.mkDerivation {
  name = "isa-rip";
  src = ./.;
  nativeBuildInputs = [
    libpcap
    pandoc
    haskellPackages.pandoc-citeproc
    texlive.combined.scheme-small
  ];
}
