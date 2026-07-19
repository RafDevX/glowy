package main

var recorded int

func record() bool {
	recorded = 1

	return true
}

func main() {
	// glowy::label::{private}
	privateDecision := true

	recorded = 0
	_ = privateDecision && record()

	// glowy::assert::{private}
	var _ = recorded
}
