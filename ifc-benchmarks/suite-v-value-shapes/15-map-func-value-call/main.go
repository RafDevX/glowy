package main

import "fmt"

func echo(s string) string { return s }

func main() {
	// glowy::label::{secret}
	tainted := "hidden"

	handlers := map[string]func(string) string{
		"echo": echo,
	}

	out := handlers["echo"](tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
