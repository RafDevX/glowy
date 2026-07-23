package main

import "fmt"

// glowy::label::{alice}
const alice = "alice"

// glowy::label::{bob}
const bob = "bob"

// glowy::label::{charlie}
const charlie = "charlie"

// glowy::label::{david}
const david = "david"

func main() {
	// glowy::label::{high}
	var x = "some string"

	// glowy::label::{private}
	z := 0

	var m, n, o, p int

	switch x + "..." {
	case "hello":
		z += 2
	case "`" + alice + "`":
		z += len(david)
	case bob:
		z += 5
		m += 4
	case charlie:
	default:
		n += 3
	case david:
		o = 2
		fallthrough
	case "goodbye":
		p = m + 1
	}

	// glowy::assert::{high, alice, bob}
	fmt.Println(m)
	// glowy::assert::{high, alice, bob, charlie, david}
	fmt.Println(n, o, p)
	// glowy::assert::{private, high, alice, david, bob}
	fmt.Println(z)
}
