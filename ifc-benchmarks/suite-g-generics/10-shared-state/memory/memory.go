package memory

var current any

func Replace[T any](next T) any {
	previous := current
	current = next

	return previous
}
