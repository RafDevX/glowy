package main

import "fmt"

type Source [1]string
type Copy [1]string

func main() {
	// glowy::label::{secret}
	secret := "hidden"

	source := Source{secret}
	copied := Copy(source)
	source[0] = "public"

	// glowy::assert::{secret}
	fmt.Println(copied[0])

	// glowy::assert::{}
	fmt.Println(source[0])
}
