package main

import "fmt"

type Tagged struct{}

func (Tagged) Name() string {
	return "tagged"
}

type Person struct {
	Name string
}

func main() {
	// glowy::label::{high}
	const secret = "secret"

	person := Person{Name: secret}

	field := person.Name

	// glowy::assert::{high}
	fmt.Println(field)

	var tagged Tagged
	method := tagged.Name()

	// glowy::assert::{}
	fmt.Println(method)
}
