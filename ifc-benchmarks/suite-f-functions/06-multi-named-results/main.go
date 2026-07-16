package main

import "fmt"

func split(tag string, secret string) (slot, plus bool, label string, _ int) {
	slot = true
	plus = false
	label = tag + secret

	return
}

func main() {
	// glowy::label::{high}
	const secret = "x"

	a, b, c, _ := split("tag-", secret)

	// glowy::assert::{}
	fmt.Println(a)
	// glowy::assert::{}
	fmt.Println(b)
	// glowy::assert::{high}
	fmt.Println(c)
}
