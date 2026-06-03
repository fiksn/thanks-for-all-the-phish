{
  description = "thanks-for-all-the-phish";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        drawbridge = pkgs.python313Packages.buildPythonPackage rec {
          pname = "drawbridge";
          version = "0.1.2";
          pyproject = true;

          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-phgxiUIyt+px5+dwwx4+cAL5P8QqYvLXLOfTq/sMofE=";
          };

          build-system = [ pkgs.python313Packages.hatchling ];
          dependencies = [ pkgs.python313Packages.httpx ];

          doCheck = false;
        };

        pythonEnv = pkgs.python313.withPackages (ps: with ps; [
          google-api-python-client
          google-auth
          google-auth-oauthlib
          google-auth-httplib2
          imapclient
          dkimpy
          dnspython
          tldextract
          beautifulsoup4
          google-cloud-pubsub
          rapidfuzz
          confusable-homoglyphs
          drawbridge
          httpx
          olefile
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [ pythonEnv ];
          shellHook = ''
            echo "[flake] $(python --version) with deps from nixpkgs"
          '';
        };
      });
}
