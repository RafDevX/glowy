fn main() {
    // sadly this will force recompilation not just for tests, but also for
    // every single configuration (even `cargo build` without `cfg(test)`)
    // See: https://github.com/rust-lang/cargo/issues/1581
    println!("cargo::rerun-if-changed=../ifc-benchmarks");
}
