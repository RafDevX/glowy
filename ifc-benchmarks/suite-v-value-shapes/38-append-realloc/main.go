package main

import "fmt"

func main() {
	original := []string{"public"}
	grown := append(original, "")

	// glowy::label::{secret}
	secret := "hidden"
	grown[0] = secret

	// glowy::assert::{}
	fmt.Println(original[0])

	// glowy::assert::{secret}
	fmt.Println(grown[0])
}
