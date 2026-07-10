{
  description = "WordPress JWT Auth plugin — dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    composition-c4.url = "github:fossar/composition-c4";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      composition-c4,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ composition-c4.overlays.default ];
        };
        inherit (pkgs) lib stdenvNoCC;

        php = pkgs.php84.withExtensions (
          { enabled, all }:
          enabled
          ++ (with all; [
            curl
            mbstring
            openssl
            tokenizer
            fileinfo
          ])
        );

        composerData = builtins.fromJSON (builtins.readFile ./composer.json);

        pname = "jwt-auth";
        version = composerData.version;
        src = self;

        # -------------------------------------------------------------- #
        # PHP / Composer vendor dependencies                               #
        # c4.fetchComposerDeps reads composer.lock per-package via        #
        # builtins.fetchGit — no hash needed.                             #
        # -------------------------------------------------------------- #
        composerDeps = pkgs.c4.fetchComposerDeps {
          inherit src;
        };

        # ---------------------------------------------------------------- #
        # Final plugin assembly                                            #
        # ---------------------------------------------------------------- #
        pluginPackage = stdenvNoCC.mkDerivation {
          inherit
            pname
            version
            src
            composerDeps
            ;

          nativeBuildInputs = [
            php
            php.packages.composer
            pkgs.c4.composerSetupHook
          ];

          buildPhase = ''
            runHook preBuild
            composer --no-ansi install --no-dev --no-interaction --optimize-autoloader
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            pluginDir="$out/share/wordpress/plugins/jwt-auth"
            mkdir -p "$pluginDir"

            cp jwt-auth.php README.md LICENSE "$pluginDir/"
            # -L dereferences: composition-c4 installs vendor/ as symlinks into the
            # Nix store; the distributable plugin must contain real, self-contained files.
            cp -rL src vendor assets "$pluginDir/"

            # Stamp the WordPress plugin header version from composer.json, which is the
            # single source of truth (Release Please bumps it). WordPress and the update
            # checker read this header to detect new versions.
            sed -i -E "s|^([[:space:]]*\* Version:[[:space:]]*).*|\1${version}|" "$pluginDir/jwt-auth.php"

            runHook postInstall
          '';

          meta = {
            description = composerData.description;
            license = lib.licenses.mit;
            platforms = lib.platforms.all;
          };
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            php
            pkgs.php84Packages.composer
          ];

          shellHook = ''
            echo "PHP $(php --version | head -1)"
            echo "Composer $(composer --version)"
          '';
        };

        packages = {
          default = pluginPackage;

          # ---------------------------------------------------------------- #
          # Deterministic, ready-to-install zip (top-level jwt-auth/).       #
          # nix build .#zip -> result/jwt-auth.zip                          #
          # ---------------------------------------------------------------- #
          zip = stdenvNoCC.mkDerivation {
            name = "jwt-auth-zip-${version}";
            nativeBuildInputs = [ pkgs.zip ];
            buildCommand = ''
              mkdir -p tmp/jwt-auth
              cp -r ${pluginPackage}/share/wordpress/plugins/jwt-auth/. tmp/jwt-auth/
              chmod -R u+w tmp
              mkdir -p "$out"
              (cd tmp && zip -r -X "$out/jwt-auth.zip" jwt-auth)
            '';
          };
        };
      }
    );
}
