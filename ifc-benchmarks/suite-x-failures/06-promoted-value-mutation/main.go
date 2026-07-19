package main

import "fmt"

// glowy::label::{private}
const tag = ">> "

type Inner struct {
	value string
}

func (i *Inner) Store(msg string) {
	i.value = tag + msg
}

type Outer struct {
	Inner
}

func main() {
	var outer Outer

	// glowy::label::{high}
	const secret = "hidden"

	outer.Store(secret)

	// glowy::assert::{high, private}
	fmt.Println(outer.value)
}
