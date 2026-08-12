# Glowy

Glowy is a Rust static analyzer for finding potentially insecure information
flows in Go modules. It tracks explicit and control-flow-dependent propagation
across files and packages, then checks the resulting labels against the defined
security policy.

This crate is the base analysis library, for programmatic use cases. A more
user-friendly CLI frontend is available:
[`glowy-cli`](https://crates.io/crates/glowy-cli).

Documentation: [docs.rs](https://docs.rs/glowy), [mirror](https://glowy.rso.pt)

## Labels and Annotations

Annotations are line comments applying to the following declaration, assignment,
send, call, or expression as appropriate:

- `glowy::label::{x, y}` adds tags.
- `glowy::revoke::{x, y}` removes tags.
- `glowy::allow::{x, y}` permits only the listed tags on the mentioned axes.
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

## Scope and Status

By default, tests are excluded and at most 256 independent build-tag
permutations are analyzed; both are configurable via `glowy.toml`. Glowy reports
unsupported or potentially unsound Go constructs instead of silently treating
them as safe.

The (currently known) chief analyzer soundness gaps are described in
[`OUT_OF_SCOPE.md`](https://github.com/RafDevX/glowy/blob/master/OUT_OF_SCOPE.md).

_Note: Glowy's behavior is undefined for invalid Go programs, but a best-effort
attempt is made to report useful information for simple mistakes, such as tokens
failing parsing expectations._
