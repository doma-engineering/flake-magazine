{
    description = "A very basic flake";

    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs";
    };

  outputs = { self, nixpkgs }: 
    let 
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      # npkgs = pkgs.nodePackages;
    in
    {
        packages.x86_64-linux.hello = pkgs.hello;
        packages.x86_64-linux.default = self.packages.x86_64-linux.hello;

        devShell.x86_64-linux = pkgs.mkShell {
            buildInputs = [ 
                pkgs.zig
                pkgs.zls

                pkgs.nodejs
            ];
        };
    };
}
