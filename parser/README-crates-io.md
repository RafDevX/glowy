# Glowy Go Parser

Glowy is a Rust static analyzer for finding potentially insecure information
flows in Go modules. It tracks explicit and control-flow-dependent propagation
across files and packages, then checks the resulting labels against the defined
security policy.

This crate is the underlying Go parser used by the
[`glowy`](https://crates.io/crates/glowy) library, but it may be used for other
applications.
