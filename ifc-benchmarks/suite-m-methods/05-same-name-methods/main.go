package main

import "fmt"

type Sender struct{}

func (Sender) Tag(msg string) string {
	return "send: " + msg
}

type Logger struct{}

func (Logger) Tag(prefix string, msg string) string {
	return prefix + ": " + msg
}

func main() {
	var sender Sender
	var logger Logger

	// glowy::label::{high}
	const secret = "Alice"

	a := sender.Tag(secret)
	b := logger.Tag("hello", secret)

	// glowy::assert::{high}
	fmt.Println(a, b)
}
