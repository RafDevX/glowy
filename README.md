# Glowy

Glowy is a Rust static analyzer for finding potentially insecure information
flows in Go modules. It tracks explicit and control-flow-dependent propagation
across files and packages, then checks the resulting labels against the defined
security policy.

This repository contains the latest version of Glowy, heavily enhanced and
adjusted for real-world analysis, as developed by
[Rafael Oliveira](https://github.com/RafDevX) within the scope of his
[Master's Degree Project](https://github.com/RafDevX/master-thesis) at KTH Royal
Institute of Technology. However, Glowy's initial conceptualization and
[first prototype](https://github.com/ist199211-ist19311/glowy-langsec) is the
work of both [Rafael Oliveira](https://github.com/RafDevX) and
[Diogo Correia](https://github.com/diogotcorreia) as part of a joint project for
KTH course DD2525 Language-Based Security. Most of the code has been completely
rewritten for robustness, soundness fixes, and feature support; see the
[diff](https://github.com/RafDevX/glowy/compare/langsec-project-submission...master).

## Quick Start

In order to analyze a Go source file using the Glowy binary, one need only:

```console
git clone git@github.com:RafDevX/glowy.git
cd glowy
cargo run --release -- path/to/go/module
```

Add `--strict` to upgrade warnings to errors.

Glowy automatically enables its
[base security policy](.lib/base-security-policy.toml), which recognizes common
secret sources, untrusted input, and disclosure sinks. It is deliberately based
on heuristics and just a starting point, not a security guarantee.

## Labels and Annotations

Annotations are line comments applying to the following declaration, assignment,
send, call, or expression as appropriate:

- `glowy::label::{x, y}` adds tags.
- `glowy::revoke::{x, y}` removes tags.
- `glowy::allow::{x, y}` permits only the listed values on the mentioned axes.
- `glowy::deny::{x, y}` rejects any matching tag.
- `glowy::assert::{x, y}` checks the inferred label, which is useful in tests.

Tags may be plain (`secret`), axis-bound (`integrity:untrusted`), or axis
wildcards (`integrity:*`). For example, these checks report confidentiality and
integrity violations, respectively:

```go
// glowy::label::{secret}
password := readPassword()
// glowy::deny::{secret}
fmt.Println(password)
```

```go
// glowy::label::{integrity:untrusted}
name := request.FormValue("name")
// glowy::allow::{integrity:trusted}
store(name)
```

An allow-sink first restricts appraisal to its named axes (while retaining
axis-free tags), then performs a whitelist check. A deny-sink is a blacklist
check against the complete label.

Note that the shorthands `$tag` and `?tag` can be used to mean `secret:tag` and
`untrusted:tag`, respectively. This makes it simpler to bind tags to these two
axes.

Directives may be provided via source-code annotations (as shown above), via
blanket directives (defined in a `glowy.toml` file), or via explicit labeling
of struct type fields through `glowy:"x, y"`-formatted field tags.

## Project-Specific Policy

Place `glowy.toml` beside `go.mod`. This compact example shows the full schema:

```toml
verbose = false
inherit_base_policy = true
excluded_base_blanket_directives = ["fmt.Println"]
include_tests = false
max_build_permutations = 256

[sources]
"os.Getenv#0~=TOKEN" = ["secret:env"]

[revocations]
"example.com/app.sanitize" = ["integrity:untrusted"]

[allow_sinks]
"example.com/app.publish#0" = ["integrity:trusted"]

[deny_sinks]
"fmt.Println" = ["secret:*"]
```

Targets use full Go import paths; predeclared functions use `builtin`, such as
`builtin.println`. `#N` selects a zero-indexed argument position. On sources and
revocations, `->N,M` selects zero-indexed result positions and `#N=value` (or
`~=` for a fuzzy match) makes the rule conditional.

Eject the complete base policy as an editable template with:

```console
cargo run --release -- base-security-policy --eject
```

## Correctness Benchmarks

This repository includes a directory [`ifc-benchmarks/`](/.ifc-benchmarks) which
contains several Go modules illustrating how to provide annotations and what
kinds of features are supported by the analyzer. These examples may be fed
directly as input to the tool, and in fact double as tests to the analyzer which
may be run by means of the command `cargo make ifc-benchmarks`.

## Scope and Status

By default, tests are excluded and at most eight independent build-tag
dimensions are enumerated; both are configurable above. Glowy reports
unsupported or potentially unsound Go constructs instead of silently treating
them as safe.

The (currently known) chief analyzer soundness gaps are described in
[`OUT_OF_SCOPE.md`](./OUT_OF_SCOPE.md), with some of them being illustrated by
the modules in the dedicated benchmarks suite
[`ifc-benchmarks/suite-x-failures`](ifc-benchmarks/suite-x-failures). These
cover difficult cases involving assignment-order, aliasing/mutation,
dynamic-dispatch, and concurrency, among others.

_Note: Glowy's behavior is undefined for invalid Go programs, but a best-effort
attempt is made to report useful information for simple mistakes, such as tokens
failing parsing expectations._
