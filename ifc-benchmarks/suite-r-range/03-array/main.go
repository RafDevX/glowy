package main

import "fmt"

func main() {
	// glowy::label::{alice}
	alice := 14
	// glowy::label::{bob}
	bob := 21
	// glowy::label::{charlie}
	charlie := 39

	arr := [...]int{0, alice, bob, charlie, 48}
	length := len(arr)

	// glowy::assert::{}
	fmt.Println(length)

	// glowy::assert::{alice, bob, charlie}
	fmt.Println(arr)

	// glowy::assert::{bob}
	fmt.Println(arr[2])

	for i, v := range arr {
		// glowy::assert::{alice, bob, charlie}
		fmt.Println(i, v)
	}

	for i := range length {
		// glowy::assert::{}
		fmt.Println(i)

		// glowy::assert::{alice, bob, charlie}
		fmt.Println(arr[i])
	}
}
