package main

import "fmt"

func main() {
	// glowy::label::{secret}
	secretIndex := 1

	array := [...]int{10, 20}
	slice := []int{10, 20}
	text := "ab"
	mapping := map[int]string{0: "zero", 1: "one"}

	// glowy::assert::{}
	fmt.Println(array[0], slice[0], text[0], mapping[0])

	// glowy::assert::{secret}
	fmt.Println(array[secretIndex])
	// glowy::assert::{secret}
	fmt.Println(slice[secretIndex])
	// glowy::assert::{secret}
	fmt.Println(text[secretIndex])

	value, ok := mapping[secretIndex]

	// glowy::assert::{secret}
	fmt.Println(value, ok)

	array[secretIndex] = 0
	slice[secretIndex] = 0

	// glowy::assert::{secret}
	fmt.Println(array[0], array[1], slice[0], slice[1])
}
