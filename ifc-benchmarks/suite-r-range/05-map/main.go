package main

import "fmt"

// glowy::label::{high}
const high = "high"

func main() {
	// glowy::label::{alice}
	alice := 14
	// glowy::label::{bob}
	bob := 21
	// glowy::label::{charlie}
	charlie := 39

	m := map[string]int{"nothing": 0, "alice": alice, "bob": bob, high: 48}

	// glowy::assert::{alice, bob, high}
	fmt.Println(m, len(m))

	for k, v := range m {
		m["charlie"] = charlie

		// glowy::assert::{alice, bob, charlie, high}
		fmt.Println(k, v)
	}

	// glowy::assert::{alice, bob, charlie, high}
	fmt.Println(m, len(m))

	// glowy::assert::{bob}
	fmt.Println(m["bob"])
}
