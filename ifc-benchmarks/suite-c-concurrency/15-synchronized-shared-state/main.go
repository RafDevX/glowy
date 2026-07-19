package main

import "fmt"

var published string

func main() {
	// glowy::label::{permission}
	allowed := true

	done := make(chan struct{})

	go func() {
		if allowed {
			published = "available"
		}

		close(done)
	}()

	<-done

	// glowy::assert::{permission}
	fmt.Println(published)
}
