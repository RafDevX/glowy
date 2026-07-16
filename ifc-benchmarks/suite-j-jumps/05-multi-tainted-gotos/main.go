package main

import "fmt"

// glowy::label::{alice}
const alice = 1

// glowy::label::{bob}
const bob = 2

func main() {
	x := 0

	if alice > 0 {
		goto End
	}

	if bob > 0 {
		goto End
	}

	x = 3

End:
	// glowy::assert::{alice, bob}
	fmt.Println(x)
}
