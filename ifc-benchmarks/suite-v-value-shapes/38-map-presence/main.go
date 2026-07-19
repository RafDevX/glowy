package main

import "fmt"

func main() {
	// glowy::label::{membership}
	includeEntry := true

	var optional map[string]int
	if includeEntry {
		optional = map[string]int{"token": 0}
	}

	_, ok := optional["token"]

	// glowy::assert::{membership}
	fmt.Println(optional == nil, ok)
}
