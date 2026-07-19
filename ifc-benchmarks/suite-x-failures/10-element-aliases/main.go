package main

import "fmt"

func main() {
	// glowy::label::{high}
	secret := 42

	nested := [][]int{{0}}
	row := nested[0]
	row[0] = secret

	mappings := []map[string]int{{"token": 0}}
	selectedMapping := mappings[0]
	selectedMapping["token"] = secret

	channels := []chan int{make(chan int, 1)}
	selected := channels[0]
	selected <- secret

	// glowy::assert::{high}
	fmt.Println(nested[0][0], mappings[0]["token"], <-channels[0])
}
