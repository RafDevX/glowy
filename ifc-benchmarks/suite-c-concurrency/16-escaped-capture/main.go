package main

import "fmt"

var published string

func launch(enabled bool, done chan struct{}) {
	// glowy::label::{secret}
	message := "hidden"

	if enabled {
		go func() {
			published = message
			close(done)
		}()
	} else {
		close(done)
	}
}

func main() {
	// glowy::label::{permission}
	allowed := true

	done := make(chan struct{})

	launch(allowed, done)
	<-done

	// glowy::assert::{secret, permission}
	fmt.Println(published)
}
