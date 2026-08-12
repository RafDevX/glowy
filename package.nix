{
  lib,
  rustPlatform,
  pkg-config,
}:
rustPlatform.buildRustPackage {
  pname = "glowy-cli";
  version = "1.0.0";

  nativeBuildInputs = [ pkg-config ];

  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;

  meta = with lib; {
    description = "Information flow control analysis for Go";
    homepage = "https://github.com/RafDevX/glowy";
    license = licenses.mit;
    mainProgram = "glowy-cli";
  };
}
