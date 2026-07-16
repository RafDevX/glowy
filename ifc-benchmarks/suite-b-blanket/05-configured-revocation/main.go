package main

import "fmt"
import "strings"

func redact(value string) string { return strings.Repeat("*", len(value)) }

func main() {
	// glowy::label::{public, secret}
	value := "message"

	redacted := redact(value)

	// glowy::assert::{public}
	fmt.Println(redacted)
}
