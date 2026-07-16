package main

import "fmt"

// glowy::label::{alice}
const alice = 5

// glowy::label::{bob}
const bob = 0

// glowy::label::{charlie}
const charlie = 3

func main() {
	breakpoint := alice

	var fib func(n int) int

	fib = func(n int) int {
		innerChecker := func(n int) bool { return n == breakpoint }

		if innerChecker(n) {
			return 0
		} else {
			return n + fib(n-1)
		}
	}

	breakpoint = bob

	// glowy::assert::{bob, charlie}
	fmt.Println(fib(charlie))
}
