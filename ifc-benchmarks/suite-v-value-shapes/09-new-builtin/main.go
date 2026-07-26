package main

import "net/http"

// glowy::label::{secret}
const secret = 3

type Box struct {
	value string
}

func allocate[T any]() *T {
	return new(T)
}

func main() {
	box := new(Box)
	headers := make(http.Header)
	headers.Set("Accept", "application/json")

	// glowy::assert::{}
	var _ = box.value

	first := []int{secret}

	second := new(first)

	// glowy::assert::{secret}
	var _ = (*second)[0] + 2

	var _ = allocate[string]()
}
