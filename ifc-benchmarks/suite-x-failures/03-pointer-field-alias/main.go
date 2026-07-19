package main

import "fmt"

type Contents struct {
	pointed *string
}

func (c Contents) WriteReference(value string) {
	*c.pointed = value
}

func main() {
	// glowy::label::{secret}
	const secret = "red"

	pointed := ""
	contents := Contents{pointed: &pointed}

	contents.WriteReference(secret)

	// glowy::assert::{secret}
	fmt.Println(pointed)
}
