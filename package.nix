{
  lib,
  rustPlatform,
  openssl,
  pkg-config,
}:
rustPlatform.buildRustPackage {
  pname = "glowy-cli";
  version = "0.1.0";

  nativeBuildInputs = [ pkg-config ];
  #buildInputs = [ openssl ];

  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;

  meta = with lib; {
    description = "A short description of your program";
    homepage = "https://github.com/RafDevX/glowy";
    license = licenses.mit;
    mainProgram = "glowy-cli";
  };
}
