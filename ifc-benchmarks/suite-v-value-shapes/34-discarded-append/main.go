package main

import "fmt"

func main() {
	// glowy::label::{high}
	secret := 42

	storage := make([]int, 1, 2)
	alias := storage

	_ = append(storage, secret)

	recovered := alias[:2][1]

	// glowy::assert::{high}
	fmt.Println(recovered)
}
