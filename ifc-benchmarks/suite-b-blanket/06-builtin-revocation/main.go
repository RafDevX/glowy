package main

import "fmt"

func main() {
	// glowy::label::{length}
	text := "secret"
	// glowy::assert::{}
	fmt.Println(len(text))

	// glowy::label::{conditional}
	publicText := "public"
	// glowy::assert::{conditional}
	fmt.Println(len(publicText))

	// glowy::label::{allocation}
	size := 2
	// glowy::assert::{}
	fmt.Println(make([]int, size))

	{
		len := func(value string) string { return value }

		// glowy::assert::{length}
		fmt.Println(len(text))
	}
}
