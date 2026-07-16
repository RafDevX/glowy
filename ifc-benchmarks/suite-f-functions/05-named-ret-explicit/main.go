package main

import "fmt"

func resolve(input string) (err string) {
	err = input

	return err
}

func main() {
	// glowy::label::{high}
	const secret = "boom"

	resolved := resolve(secret)

	// glowy::assert::{high}
	fmt.Println(resolved)
}
