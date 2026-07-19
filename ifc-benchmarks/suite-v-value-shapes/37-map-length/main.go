package main

import "fmt"

func main() {
	// glowy::label::{membership}
	includeEntry := true

	entries := map[string]int{}
	if includeEntry {
		entries["token"] = 0
	}

	// glowy::assert::{membership}
	fmt.Println(len(entries))
}
