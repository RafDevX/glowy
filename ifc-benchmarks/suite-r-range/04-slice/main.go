package main

import "fmt"

func main() {
	// glowy::label::{alice}
	alice := 14
	// glowy::label::{bob}
	bob := 21
	// glowy::label::{charlie}
	charlie := 39

	s := []int{0, alice, bob, charlie, 48}
	length := len(s)

	// glowy::assert::{}
	fmt.Println(length)

	// glowy::assert::{alice, bob, charlie}
	fmt.Println(s)

	// glowy::assert::{bob}
	fmt.Println(s[2])

	for i, v := range s {
		// glowy::assert::{}
		fmt.Println(i)

		// glowy::assert::{alice, bob, charlie}
		fmt.Println(v)
	}

	for i := range length {
		// glowy::assert::{}
		fmt.Println(i)

		// glowy::assert::{alice, bob, charlie}
		fmt.Println(s[i])
	}
}
