package main

import "fmt"

type ID int

func main() {
	// glowy::label::{high}
	const secret = 42

	u := ID(secret)

	// glowy::assert::{high}
	fmt.Println(u)
}
