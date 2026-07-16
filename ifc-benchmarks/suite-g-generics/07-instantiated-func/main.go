package main

import "fmt"

func echo[T any](x T) T {
	return x
}

func main() {
	// glowy::label::{secret}
	tainted := "private"

	echoStr := echo[string]

	out := echoStr(tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
