package main

import "fmt"

// glowy::label::{high}
const high = "high"

func main() {
	// glowy::label::{alice}
	alice := 14
	// glowy::label::{bob}
	bob := 21
	// glowy::label::{charlie}
	charlie := 39

	m := map[string]int{"nothing": 0, "alice": alice, "bob": bob, high: 48}

	// glowy::assert::{alice, bob, high}
	fmt.Println(m, len(m))

	for k, v := range m {
		m["charlie"] = charlie

		// glowy::assert::{alice, bob, charlie, high}
		fmt.Println(k, v)
	}

	// glowy::assert::{alice, bob, charlie, high}
	fmt.Println(m, len(m))

	// glowy::assert::{bob}
	fmt.Println(m["bob"])

	// glowy::label::{membership}
	includeSecond := true
	entries := map[int]int{1: 1}
	if includeSecond {
		entries[2] = 2
	}

	visits := 0
	sequence := 0
	last := 0
	for key := range entries {
		visits++
		sequence = sequence*10 + key
		last = key

		// glowy::assert::{membership}
		fmt.Println(key)
	}

	// glowy::assert::{membership}
	fmt.Println(visits, sequence, last)

	// glowy::label::{deletion}
	removeSecond := true
	candidates := map[int]int{1: 0, 2: 0}
	visited := 0
	for key := range candidates {
		if key == 1 && removeSecond {
			delete(candidates, 2)
		}
		visited = visited*10 + key
	}

	// glowy::assert::{deletion}
	fmt.Println(visited, len(candidates))
}
