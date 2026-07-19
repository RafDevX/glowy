package main

import (
	"fmt"
	"shared-state/memory"
)

func main() {
	// glowy::label::{secret}
	launchCode := "private"

	// glowy::label::{high}
	fog := 4

	memory.Replace[string](launchCode)
	previous := memory.Replace[int](fog)

	// glowy::assert::{secret}
	fmt.Println(previous)
}
