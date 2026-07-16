package upper

import "cross-pkg-promoted-field/lower"

type Server struct {
	lower.Base
}

func New() Server {
	return Server{Base: lower.Base{}}
}
