{
  description = "pyCertWiz: certificate manager for the UK e-Science CA and ACME CAs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = (builtins.fromTOML (builtins.readFile ./pyproject.toml)).project.version;
    in
    {
      packages = forAll (pkgs:
        let
          py = pkgs.python3Packages;
          pycertwiz = py.buildPythonApplication {
            pname = "pycertwiz";
            inherit version;
            pyproject = true;
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: _type:
                let rel = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
                in rel == "pyproject.toml" || rel == "README.md" || rel == "LICENSE"
                   || rel == "src" || pkgs.lib.hasPrefix "src/" rel;
            };
            build-system = [ py.setuptools py.wheel ];
            dependencies = [ py.cryptography py.pyside6 py.keyring ];
            nativeBuildInputs = [ pkgs.qt6.wrapQtAppsHook ];
            buildInputs = [ pkgs.qt6.qtbase pkgs.qt6.qtsvg ]
              ++ pkgs.lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.qt6.qtwayland;
            # Wrap the Python entry points (not the Qt binaries) with Qt's plugin paths.
            dontWrapQtApps = true;
            preFixup = ''makeWrapperArgs+=("''${qtWrapperArgs[@]}")'';
            postInstall = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
              install -Dm644 ${./packaging/icons/pycertwiz.svg} \
                $out/share/icons/hicolor/scalable/apps/io.github.rob_c.pyCertWiz.svg
              install -Dm644 ${./packaging/linux/io.github.rob_c.pyCertWiz.desktop} \
                $out/share/applications/io.github.rob_c.pyCertWiz.desktop
              install -Dm644 ${./packaging/linux/io.github.rob_c.pyCertWiz.metainfo.xml} \
                $out/share/metainfo/io.github.rob_c.pyCertWiz.metainfo.xml
            '';
            pythonImportsCheck = [ "pycert" "pycert.gui" ];
            meta = {
              description = "Certificate manager for the UK e-Science CA and ACME CAs";
              homepage = "https://github.com/rob-c/pyCertWiz";
              license = pkgs.lib.licenses.gpl2Plus;
              mainProgram = "pycertwiz";
              platforms = pkgs.lib.platforms.unix;
            };
          };
        in
        { inherit pycertwiz; default = pycertwiz; });

      apps = forAll (pkgs: {
        default = { type = "app"; program = "${self.packages.${pkgs.system}.default}/bin/pycertwiz"; };
      });
    };
}
