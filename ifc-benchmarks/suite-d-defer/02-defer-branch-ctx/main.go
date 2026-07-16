package main

import "fmt"

func main() {
	// glowy::label::{secret}
	var secret = 42

	if secret > 0 {
		defer observe(1)
	}

	var pub = 7

	// glowy::assert::{}
	fmt.Println(pub)
}

func observe(a int) {
	// glowy::assert::{secret}
	fmt.Println(a)
}
