//go:build !windows

package main

// glowy::label::{special}
const specialGreeting = "hello"

func makeGreeting(name string) string {
	return specialGreeting + " " + name
}
