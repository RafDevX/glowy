package main

import "fmt"

type policy interface{ status() int }

type permitted struct{}
type rejected struct{}

func (permitted) status() int { return 200 }
func (rejected) status() int  { return 403 }

func main() {
	// glowy::label::{secret}
	restrictAccess := true

	var response policy = permitted{}

	if restrictAccess {
		response = rejected{}
	}

	status := response.status()

	// glowy::assert::{secret}
	fmt.Println(status)
}
