package main

import "fmt"

func main() {
	// glowy::label::{descriptor}
	secret := 1

	var optional []int
	if secret > 0 {
		optional = []int{}
	}

	// glowy::assert::{descriptor}
	fmt.Println(optional == nil)

	sized := make([]int, secret)

	// glowy::assert::{descriptor}
	fmt.Println(len(sized))
	// glowy::assert::{descriptor}
	fmt.Println(cap(sized))
}
