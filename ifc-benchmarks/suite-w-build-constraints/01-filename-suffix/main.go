//go:build linux || windows

package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 42

	pad := padding()
	out := secret + pad

	// glowy::assert::{high, selected}
	fmt.Println(out)
}
