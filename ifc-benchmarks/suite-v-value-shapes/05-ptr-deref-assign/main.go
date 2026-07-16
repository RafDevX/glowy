package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 7

	x := 0
	p := &x

	*p = secret

	// glowy::assert::{high}
	fmt.Println(*p)

	pos := []int{}
	pp := &pos

	*pp = append(*pp, secret)

	// glowy::assert::{high}
	fmt.Println((*pp)[0])
}
