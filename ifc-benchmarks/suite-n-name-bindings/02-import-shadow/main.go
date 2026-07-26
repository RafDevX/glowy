package main

import "fmt"

type output struct {
	Println string
}

func main() {
	fmt.Println("public")

	// glowy::label::{secret}
	secret := "hidden"

	fmt := output{Println: secret}

	// glowy::assert::{secret}
	var _ = fmt.Println
}
