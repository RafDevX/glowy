package main

import "fmt"

func main() {
	// glowy::label::{secret}
	element := 42

	// glowy::assert::{}
	fmt.Println(len([1]int{element}), cap([1]int{element}))
}
