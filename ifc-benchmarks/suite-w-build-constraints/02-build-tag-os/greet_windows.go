//go:build windows

package main

// glowy::label::{special}
const specialGreeting = "hi"

func makeGreeting(name string) string {
	return specialGreeting + " " + name
}
