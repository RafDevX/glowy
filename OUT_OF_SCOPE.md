# Out of Scope Functionality & Known Soundness Limitations

Glowy's analysis is not sound for arbitrary Go 1.26 programs.

Due to simplicity requirements and time constraints, this project intentionally
does not handle some complicated cases that are relevant to information-flow
security and could represent real security threats, even if
some of them are somewhat common in normal Go programs.

The primary and most relevant (known) out of scope items are detailed in the
present document.

## Analysis Boundary

- External dependencies are not resolved, just modeled as black boxes, meaning
  that any potential side-effects or insecure flows in their code are invisible
  (e.g., an external function accessing a `TOKEN` env var).
- Assembly, cgo, `unsafe`, reflection, `//go:linkname`, plugins, finalizers,
  signals, and similar runtime mechanisms can read/write or invoke code outside
  the model (e.g., `reflect.ValueOf(&pub).Elem().Set(reflect.ValueOf(secret))`).
- `//go:embed`-supplied bytes and other non-Go/generated-at-build-time inputs
  are invisible unless represented by analyzed Go or policy annotations.
- Directory loading considers real, regular `.go` files only: symlinks are
  skipped.
- Nested modules are not traversed, workspace modules are not discovered, and
  external dependencies are not loaded through module, `replace`, or vendor
  resolution.
- Build worlds exclude multiple simultaneous `GOOS`, `GOARCH`, or compiler tags,
  but do not enforce valid OS/architecture pairs or implied architecture feature
  tags, so impossible worlds can cause false positives (e.g.,
  `//go:build js && arm64`).

## Values, Calls, and Types

- Heap locations and general pointer aliasing are not modeled (e.g.,
  `p, q:= &x, &x; *p = secret; use(*q)`).
- Nontrivial reference aliases extracted from aggregates or transferred through
  channels/interfaces are sometimes shallow or incomplete (e.g.,
  `row := matrix[0]; row[0] = secret`).
- Alias relationships between multiple results of one call may not be preserved
  (e.g., `ch, alias := pair(); ch <- secret; use(<-alias)`).
- Repeated execution of the same allocation or factory site is not always given
  a distinct abstract identity, so independent calls may incorrectly share
  state (e.g., `ch1 := factory(); ch2 := factory(); ch1 <- secret; use(<-ch2)`).
- Calls do not write mutations back to the caller through
  pointer/map/slice/channel arguments or pointer receivers, including
  promoted/reference fields (e.g., `func f(p *int){ *p = secret }`).
- Closures returned from the same factory invocation may not preserve their
  shared capture-cell relationships (e.g.,
  `read, write := cell(); write(secret); use(read())`).
- Capture realization can use a stale fallback when the current captured value
  still contains synthetic labels, silently losing or retaining outdated flows
  (e.g., `func f() func(){ return func(){ use(x) } }; f()()`).
- Recursive call cycles that transitively relay captured package values through
  function summaries are not supported and never converge.
- Distinct function and closure invocations are not fully
  call-context-sensitive, so state belonging to separate factory calls may be
  conflated (e.g., `a, b := factory(),factory(); a.Set(secret); use(b.Get())`).
- Interface implementation sets and interface-typed dynamic dispatch are not
  modeled. Statically resolvable receivers use typed method resolution, while
  truly dynamic calls fall back to a black box (e.g., `var x I = T{}; x.M()`).
- Method promotion through embedded interfaces is not modeled (e.g.,
  `type I interface { J }` where `J` declares the invoked method).
- Type-assertion success values and type-switch case/narrowing semantics are
  only label approximations, not dynamic-type analysis (e.g., `_, ok := x.(T)`).
- Generic type arguments and constraints are parsed but mostly erased, so
  type-dependent shape, method-set, conversion, and dispatch behavior is not
  specialized (e.g., `func call[T interface{ M() }](x T){ x.M() }`).
- Method expressions are not modeled distinctly from method calls and may be
  rejected or misapplied (e.g., `T.M(v)` / `(*T).M(p)`).
- Compatible alternative function values are merged, but incompatible capture
  or result summaries cannot share one callable model.
- Returned-function detection only examines top-level results, so incompatible
  functions nested in composites can be flat-merged and lose information.
- Calls to shadowed `make` and `new` are still interpreted as if invoking the
  respectively-named built-ins.
- Numeric literals use `u64`/`f64` rather than Go's arbitrary-precision constant
  model, so very large literals are not supported, and imaginary literals are
  not tokenized at all (e.g., `const z = 2i`).

## Evaluation and Control Flow

- Assignment is not implemented as Go's two-phase operation: right-hand-side
  expressions are visited before left-hand-side address/index evaluation and
  left-hand-side expressions are then evaluated and updated one by one (e.g.,
  `i, a[i] = 1, secret`).
- The analyzer commits to AST visitor order where Go leaves the relative order
  of calls and ordinary operand/index evaluation unspecified, rather than
  exploring every permitted order (e.g., `[]int{x, f()}` where `f` mutates `x`).
- Control-flow arms mutate one shared symbol state rather than isolated
  snapshots joined afterward, so an arm can observe another arm's updates and
  revocations can make joins order-dependent.
- `panic`, `recover`, run-time panics, and non-returning calls are not modeled,
  and so reachability, defers, and implicit flows can be wrong.
- Imported packages and broad initialization phases are ordered, but
  intra-package initializer dependencies are approximated, and stateful package
  initialization is replayed until labels converge instead of running once,
  meaning that non-idempotent initializers/`init` side effects can differ.
- Termination, blocking, scheduling, timing, resource use, allocation failure,
  and other covert/availability channels are outside the noninterference model.

## Concurrency

- Goroutines are analyzed as immediate calls, so execution delay, interleaving,
  happens-before logic, synchronization, and the values observable in data races
  are not explored.
- Select clauses update the same abstract state sequentially, so mutually
  exclusive receive targets can contaminate each other, especially through
  aggregate targets (e.g.,
  `select { case a[idx(0)] = <-x: case a[idx(1)] = <-y: }`).
- Goroutine effects that require argument/receiver write-back can disappear
  entirely (e.g., `go func(ch chan int){ ch<-secret }(ch)`).
