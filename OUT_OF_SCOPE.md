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
  that any potential side-effects in their code are invisible and security
  policy directives cannot be applied to their internal flows (e.g., an external
  function accessing a `TOKEN` env var).
- Assembly, cgo, `unsafe`, reflection, `//go:linkname`, plugins, finalizers,
  signals, and similar runtime mechanisms can read/write or invoke code outside
  the model.
- `//go:embed`-supplied bytes and other non-Go/generated-at-build-time inputs
  are invisible unless represented by analyzed Go or policy annotations.
- Directory loading consider real, regular `.go` files only: symlinks are
  skipped.
- Nested modules are not traversed, workspace modules are not discovered, and
  external dependencies are not loaded through module, `replace`, or vendor
  resolution.

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
- Distinct function and closure invocations are not fully
  call-context-sensitive, so state belonging to separate factory calls may be
  conflated.
- Interface implementation sets and interface-typed dynamic dispatch are not
  modeled. Name-based heuristics can therefore select the wrong method body or
  fall back to a black box (e.g., `var x I = T{}; x.M()`).
- Method promotion through embedded interfaces is not modeled (e.g.,
  `type I interface { J }` where `J` declares the invoked method).
- Type-assertion success values and type-switch case/narrowing semantics are
  only label approximations, not dynamic-type analysis (e.g., `_, ok := x.(T)`).
- Generic type arguments and constraints are parsed but mostly erased, so
  type-dependent shape, method-set, conversion, and dispatch behavior is not
  specialized.
- Method expressions are not modeled distinctly from method calls and may be
  rejected or misapplied (e.g., `T.M(v)` / `(*T).M(p)`).
- Branch-merging incompatible function values is recognized as not representable
  under the current single-function-value model and thus unsound (even if valid
  Go and holding a relevant security value), thus yielding an error.
- Calls to shadowed `make` and `new` are still interpreted as if invoking the
  respectively-named built-in functions, rather than the user-defined shadows.

## Evaluation and Control Flow

- Assignment is not implemented as Go's two-phase operation: right-hand-side
  expressions are visited before left-hand-side address/index evaluation and
  left-hand-side expressions are then evaluated and updated one by one (e.g.,
  `i, a[i] = 1, secret`).
- `panic`, `recover`, run-time panics, and non-returning calls are not modeled,
  and so reachability, defers, and implicit flows can be wrong.
- Stateful package initialization is replayed repeatedly until labels converge
  rather than executed once in Go's dependency order, so non-idempotent
  initializers/`init` side effects can differ.
- Deferred calls from inside `init` functions are executed immediately instead
  of deferred, with a soundness warning being reported.
- Termination, blocking, scheduling, timing, resource use, allocation failure,
  and other covert/availability channels are outside the noninterference model.

## Concurrency

- Goroutines are analyzed as immediate calls, so execution delay, interleaving,
  happens-before logic, synchronization, and the values observable in data races
  are not explored during analysis.
- Goroutine effects that require argument/receiver write-back can disappear
  entirely (e.g., `go func(ch chan int){ ch<-secret }(ch)`).
