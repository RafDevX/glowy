package main

import "fmt"

type Cache map[string]string

func main() {
	// glowy::label::{high}
	const secret = "top-secret"

	cache := Cache{"k": secret, "other": "public"}

	// glowy::assert::{high}
	fmt.Println(cache["k"])

	// glowy::assert::{}
	fmt.Println(cache["other"])
}
