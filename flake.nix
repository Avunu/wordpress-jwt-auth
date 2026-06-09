{
  description = "WordPress JWT Auth plugin — dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
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
      }
    );
}
