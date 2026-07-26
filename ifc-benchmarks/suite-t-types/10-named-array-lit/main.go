package main

import "fmt"

type Offset [2]int32

func main() {
	// glowy::label::{high}
	var secret int32 = 5

	o := Offset{secret, 0}

	// glowy::assert::{high}
	fmt.Println(o[0])

	// glowy::assert::{}
	fmt.Println(o[1])
}
