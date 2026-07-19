package main

import "fmt"

// glowy::label::{secret}
const secret = "hidden"

// glowy::label::{private}
const private = "internal"

func main() {
	slicePayload := []string{""}
	mapPayload := map[string]string{"message": ""}

	slices := make(chan []string, 1)
	maps := make(chan map[string]string, 1)

	slices <- slicePayload
	maps <- mapPayload

	slicePayload[0] = secret

	receivedSlice := <-slices
	receivedMap := <-maps

	receivedMap["message"] = private

	// glowy::assert::{secret}
	fmt.Println(receivedSlice[0])

	// glowy::assert::{private}
	fmt.Println(mapPayload["message"])
}
