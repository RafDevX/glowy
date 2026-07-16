use std::path::{Path, PathBuf};

#[test_generator::test_resources("ifc-benchmarks/**/go.mod")]
fn check(go_mod_path: &str) {
    let lib_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root_dir = lib_dir.parent().unwrap();

    let module_dir = Path::new(go_mod_path).parent().unwrap(); // relative
    let module_dir = root_dir.join(module_dir); // absolute

    if module_dir
        .components()
        .any(|component| component.as_os_str() == "suite-x-failures")
    {
        // this is a known failure, so we skip it here, otherwise it would
        // cause `cargo test` to report an overall failure
        return;
    }

    let analyzer = glowy::Analyzer::from_directory(module_dir).expect("failed to load module");

    analyzer
        .analyze()
        .unwrap_or_else(|errors| panic!("{errors:#?}"));
}
