package main

import "fmt"

func cell() (func() int, func(int)) {
	value := 0

	return func() int { return value }, func(next int) { value = next }
}

func main() {
	// glowy::label::{alice}
	alice := 1

	readAlice, writeAlice := cell()
	readPublic, _ := cell()

	writeAlice(alice)

	// glowy::assert::{alice}
	fmt.Println(readAlice())

	// glowy::assert::{}
	fmt.Println(readPublic())
}
