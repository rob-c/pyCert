# pyCertWiz's test environment from nixpkgs (no pip wheels: Nix has no FHS
# library paths, so Qt and cryptography come from nixpkgs itself).
{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixos-26.05.tar.gz") { } }:
let
  python = pkgs.python3.withPackages (ps: with ps; [
    cryptography
    pyside6
    keyring
    pytest
    pytest-cov
    pytest-qt
    pytest-xdist
  ]);
in
pkgs.mkShell {
  packages = [ python pkgs.openssl pkgs.xorg.xwininfo pkgs.bashInteractive pkgs.coreutils ];
  # PySide6 from nixpkgs does not bundle Qt's plugins (offscreen, xcb).
  QT_PLUGIN_PATH = "${pkgs.qt6.qtbase}/${pkgs.qt6.qtbase.qtPluginPrefix}";
  FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
  PYTHONPATH = "/work/src:/work";
}
